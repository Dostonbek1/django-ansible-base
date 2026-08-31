"""
External OAuth Token Authentication

DRF authentication class for validating incoming Bearer tokens (JWTs) against
external OAuth/OIDC providers (Entra ID, Keycloak, generic OIDC, etc.).

Key Features:
- JWT signature verification using cached JWKS keys
- Multi-provider routing via issuer claim
- Standard claims validation (issuer, audience, expiration, subject)
- Graceful fallthrough to other authentication classes for non-external-OAuth tokens

See: ANSTRAT-1611 P2 - External OAuth Token Validation
"""

import json
import logging
import ssl
import time
import urllib.request
from collections import defaultdict
from functools import lru_cache
from typing import Optional, Tuple

import jwt
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils.encoding import smart_str
from jwt import PyJWKClient
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
)
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from ansible_base.authentication.models import Authenticator, AuthenticatorUser
from ansible_base.lib.logging import log_auth_event
from ansible_base.lib.utils.settings import get_setting

logger = logging.getLogger('ansible_base.authentication.external_oauth_authentication')

User = get_user_model()


# In-memory rate limiting for JWKS refresh (per-provider, per-process)
# Key: provider ID, Value: timestamp of last refresh
_jwks_refresh_timestamps = {}
_JWKS_REFRESH_COOLDOWN = 60  # seconds - prevent excessive refreshes on signature failures


class JWKSKeyManager:
    """
    Manages JWKS key fetching and caching for JWT signature verification.

    Handles:
    - Fetching JWKS keys from provider endpoints
    - Caching with configurable TTL
    - Automatic key rotation detection
    - Provider unavailability graceful degradation
    """

    @staticmethod
    def get_cache_key(jwks_uri: str) -> str:
        """Generate cache key for JWKS keys."""
        return f"external_oauth:jwks:{jwks_uri}"

    @staticmethod
    def fetch_jwks_keys(jwks_uri: str, verify_ssl: bool = True) -> dict:
        """
        Fetch JWKS keys from provider endpoint.

        Args:
            jwks_uri: Provider's JWKS endpoint URL
            verify_ssl: Whether to verify SSL certificates

        Returns:
            dict: JWKS document with 'keys' array

        Raises:
            Exception: On network errors or invalid JSON
        """
        ssl_context = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()

        try:
            with urllib.request.urlopen(jwks_uri, context=ssl_context, timeout=10) as response:
                jwks_data = json.loads(response.read().decode('utf-8'))
                logger.debug(f"Fetched JWKS keys from {jwks_uri}")
                return jwks_data
        except Exception as e:
            logger.error(f"Failed to fetch JWKS keys from {jwks_uri}: {e}")
            raise

    @staticmethod
    def get_jwks_keys(provider_id: int, jwks_uri: str, cache_timeout: int, verify_ssl: bool = True, force_refresh: bool = False) -> Optional[dict]:
        """
        Get JWKS keys with caching and automatic refresh on key rotation.

        Args:
            provider_id: Authenticator ID (for refresh rate limiting)
            jwks_uri: Provider's JWKS endpoint URL
            cache_timeout: Cache TTL in seconds
            verify_ssl: Whether to verify SSL certificates
            force_refresh: Force fetch fresh keys (for key rotation handling)

        Returns:
            dict: JWKS document, or None if unavailable and no cached keys exist
        """
        cache_key = JWKSKeyManager.get_cache_key(jwks_uri)

        # Check refresh cooldown (prevent abuse)
        if force_refresh:
            last_refresh = _jwks_refresh_timestamps.get(provider_id, 0)
            if time.time() - last_refresh < _JWKS_REFRESH_COOLDOWN:
                logger.warning(
                    f"JWKS refresh for provider {provider_id} rate-limited "
                    f"(cooldown: {_JWKS_REFRESH_COOLDOWN}s)"
                )
                force_refresh = False

        # Try cache first (unless force refresh)
        if not force_refresh:
            cached_keys = cache.get(cache_key)
            if cached_keys is not None:
                logger.debug(f"Using cached JWKS keys for {jwks_uri}")
                return cached_keys

        # Fetch fresh keys
        try:
            jwks_data = JWKSKeyManager.fetch_jwks_keys(jwks_uri, verify_ssl)
            cache.set(cache_key, jwks_data, cache_timeout)
            if force_refresh:
                _jwks_refresh_timestamps[provider_id] = time.time()
            logger.info(f"Cached JWKS keys from {jwks_uri} (TTL: {cache_timeout}s)")
            return jwks_data
        except Exception as e:
            # Provider unavailable - try to use cached keys as fallback
            cached_keys = cache.get(cache_key)
            if cached_keys is not None:
                logger.warning(
                    f"JWKS endpoint {jwks_uri} unavailable, using cached keys: {e}"
                )
                return cached_keys
            else:
                logger.error(
                    f"JWKS endpoint {jwks_uri} unavailable and no cached keys exist: {e}"
                )
                return None


class ExternalOAuthAuthentication(BaseAuthentication):
    """
    DRF authentication class for validating external OAuth tokens (JWTs).

    Authentication flow:
    1. Extract Bearer token from Authorization header
    2. Decode JWT without verification to get issuer claim
    3. Route to matching provider by issuer (and audience if needed)
    4. Verify JWT signature using provider's JWKS keys
    5. Validate claims (issuer, audience, expiration, subject)
    6. Map token claims to AAP user
    7. Return (user, token_data) or raise AuthenticationFailed

    Returns None (fallthrough) for:
    - Non-Bearer requests
    - Non-JWT tokens
    - JWTs without issuer claim
    - JWTs from AAP itself (Workload Identity)
    - JWTs that don't match any configured provider
    """

    def authenticate(self, request):
        """
        Authenticate request using external OAuth token.

        Returns:
            tuple: (user, token_data) if authenticated
            None: If not an external OAuth token (fallthrough to next auth class)

        Raises:
            AuthenticationFailed: If token is invalid or user not found
        """
        # Step 1: Extract Bearer token
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.lower().startswith('bearer '):
            return None  # Not a Bearer token, fallthrough

        token = auth_header.split(' ', 1)[1]

        # Step 2: Decode JWT header + payload WITHOUT verification
        try:
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
        except DecodeError:
            logger.debug("Token is not a valid JWT, skipping external OAuth authentication")
            return None  # Not a JWT, fallthrough

        # Step 3: Extract issuer and audience claims
        issuer = unverified_payload.get('iss')
        if not issuer:
            logger.debug("JWT has no 'iss' claim, skipping external OAuth authentication")
            return None  # No issuer, fallthrough

        # Check if this is AAP's own JWT (Workload Identity tokens)
        aap_issuer = self._get_aap_issuer_url(request)
        if issuer == aap_issuer:
            logger.debug(f"JWT issuer matches AAP issuer ({aap_issuer}), skipping (Workload Identity token)")
            return None  # AAP-issued token, fallthrough

        audience_claim = unverified_payload.get('aud')

        # Step 4: Find matching external_oauth provider
        provider = self._find_provider(issuer, audience_claim)
        if not provider:
            logger.info(f"No external OAuth provider configured for issuer: {issuer}")
            return None  # No matching provider, fallthrough

        # Step 5-7: Validate JWT and map to user
        try:
            user, token_data = self._validate_and_authenticate(token, provider, request)
            return (user, token_data)
        except AuthenticationFailed:
            raise  # Propagate authentication failure

    def _get_aap_issuer_url(self, request) -> Optional[str]:
        """
        Get AAP's own issuer URL for Workload Identity tokens.

        This is used to distinguish AAP-issued JWTs (Workload Identity)
        from external provider JWTs.
        """
        # Try to get from settings (Workload Identity feature)
        try:
            issuer = get_setting('ANSIBLE_BASE_JWT_KEY', None)
            if issuer:
                return issuer
        except Exception:
            pass

        # Fallback: construct from request
        return request.build_absolute_uri('/')

    @lru_cache(maxsize=1)
    def _get_provider_lookup(self, cache_buster):
        """
        Build provider lookup index by issuer.

        Args:
            cache_buster: Timestamp of most recent authenticator modification
                          (forces cache invalidation when authenticators change)

        Returns:
            dict: {issuer_url: [Authenticator, ...]}
        """
        lookup = defaultdict(list)
        providers = Authenticator.objects.filter(
            enabled=True,
            category='api_auth',
            type='ansible_base.authentication.authenticator_plugins.external_oauth'
        ).order_by('order')  # Respect authenticator priority

        for provider in providers:
            issuer = provider.configuration.get('ISSUER_URL')
            if issuer:
                lookup[issuer].append(provider)

        return dict(lookup)

    def _find_provider(self, issuer: str, audience_claim=None) -> Optional[Authenticator]:
        """
        Find matching external OAuth provider by issuer (and audience if needed).

        Args:
            issuer: Token's 'iss' claim value
            audience_claim: Token's 'aud' claim value (string or list)

        Returns:
            Authenticator: Matching provider, or None if not found
        """
        # Get cache buster (most recent authenticator modification timestamp)
        latest_mod = Authenticator.objects.values('modified').order_by('-modified').first()
        cache_buster = latest_mod['modified'] if latest_mod else None

        # Get provider lookup (cached, invalidated on authenticator changes)
        provider_lookup = self._get_provider_lookup(cache_buster)
        candidates = provider_lookup.get(issuer, [])

        if not candidates:
            return None

        if len(candidates) == 1:
            return candidates[0]

        # Multiple providers with same issuer - disambiguate by audience
        if audience_claim:
            # Normalize audience to set (RFC 7519 §4.1.3 allows string or array)
            aud_set = set(audience_claim) if isinstance(audience_claim, list) else {audience_claim}

            for provider in candidates:
                provider_aud = provider.configuration.get('AUDIENCE')
                if provider_aud and provider_aud in aud_set:
                    return provider

        # Fall back to provider without AUDIENCE configured (catch-all)
        for provider in candidates:
            if not provider.configuration.get('AUDIENCE'):
                return provider

        return None

    def _validate_and_authenticate(self, token: str, provider: Authenticator, request) -> Tuple[User, dict]:
        """
        Validate JWT and map to AAP user.

        Args:
            token: Raw JWT string
            provider: Matching external OAuth provider
            request: DRF request object

        Returns:
            tuple: (user, validated_token_data)

        Raises:
            AuthenticationFailed: On validation failure or user not found
        """
        config = provider.configuration

        # Step 5: Get JWKS keys (cached or fetch)
        jwks_data = JWKSKeyManager.get_jwks_keys(
            provider_id=provider.pk,
            jwks_uri=config['JWKS_URI'],
            cache_timeout=config.get('JWKS_CACHE_TIMEOUT', 3600),
            verify_ssl=config.get('VERIFY_SSL', True),
        )

        if not jwks_data:
            logger.error(f"JWKS keys unavailable for provider {provider.name} (ID: {provider.pk})")
            raise AuthenticationFailed("Authentication service unavailable")

        # Step 6: Verify JWT signature
        try:
            validated_payload = self._verify_jwt_signature(token, jwks_data, config)
        except InvalidSignatureError:
            # Key rotation handling: retry with fresh keys
            logger.warning(f"JWT signature verification failed for provider {provider.name}, attempting key refresh")
            fresh_jwks_data = JWKSKeyManager.get_jwks_keys(
                provider_id=provider.pk,
                jwks_uri=config['JWKS_URI'],
                cache_timeout=config.get('JWKS_CACHE_TIMEOUT', 3600),
                verify_ssl=config.get('VERIFY_SSL', True),
                force_refresh=True,
            )

            if not fresh_jwks_data or fresh_jwks_data == jwks_data:
                logger.error(f"JWT signature verification failed even after key refresh for provider {provider.name}")
                raise AuthenticationFailed("Invalid token signature")

            # Retry with fresh keys
            try:
                validated_payload = self._verify_jwt_signature(token, fresh_jwks_data, config)
            except InvalidSignatureError:
                logger.error(f"JWT signature verification failed with fresh keys for provider {provider.name}")
                raise AuthenticationFailed("Invalid token signature")

        # Step 7: Map claims to user (placeholder - will be implemented in P4)
        user = self._map_token_to_user(validated_payload, provider)

        # Log successful authentication
        username = user.username if user else '<none>'
        log_auth_event(
            smart_str(
                f"User {username} authenticated via external OAuth provider {provider.name} "
                f"(issuer: {validated_payload.get('iss')}) for {request.method} {request.path}"
            )
        )

        return (user, validated_payload)

    def _verify_jwt_signature(self, token: str, jwks_data: dict, config: dict) -> dict:
        """
        Verify JWT signature and validate claims.

        Args:
            token: Raw JWT string
            jwks_data: JWKS document with public keys
            config: Provider configuration

        Returns:
            dict: Validated JWT payload

        Raises:
            AuthenticationFailed: On verification failure
        """
        issuer = config['ISSUER_URL']
        audience = config.get('AUDIENCE') or None
        algorithms = config.get('ALLOWED_ALGORITHMS', ['RS256'])

        # Use PyJWT with JWKS client
        try:
            # Create signing key from JWKS
            jwks_client = PyJWKClient(uri=None, jwks_client_options={"cache_jwk_set": False})
            jwks_client.jwk_set = jwks_data  # Inject our cached JWKS

            # Decode and verify
            validated_payload = jwt.decode(
                token,
                jwks_client.get_signing_key_from_jwt(token).key,
                algorithms=algorithms,
                issuer=issuer,
                audience=audience,
                leeway=30,  # 30 second clock drift tolerance
                options={
                    'require': ['iss', 'exp', 'sub'],
                    'verify_aud': bool(audience),
                    'verify_signature': True,
                },
            )

            return validated_payload

        except ExpiredSignatureError:
            logger.debug(f"JWT expired for provider issuer {issuer}")
            raise AuthenticationFailed("Token has expired")
        except InvalidAudienceError:
            logger.warning(f"JWT audience mismatch for provider issuer {issuer}")
            raise AuthenticationFailed("Authentication failed")
        except InvalidIssuerError:
            logger.warning(f"JWT issuer mismatch for provider issuer {issuer}")
            raise AuthenticationFailed("Authentication failed")
        except MissingRequiredClaimError as e:
            logger.warning(f"JWT missing required claim for provider issuer {issuer}: {e}")
            raise AuthenticationFailed("Authentication failed")
        except InvalidSignatureError:
            raise  # Re-raise for key rotation handling
        except InvalidTokenError as e:
            logger.warning(f"Invalid JWT for provider issuer {issuer}: {e}")
            raise AuthenticationFailed("Authentication failed")

    def _map_token_to_user(self, token_payload: dict, provider: Authenticator) -> User:
        """
        Map JWT claims to AAP user.

        This is a placeholder implementation for the PoC.
        Full implementation will be in P4 (Claim Mapping).

        Args:
            token_payload: Validated JWT payload
            provider: External OAuth provider

        Returns:
            User: AAP user

        Raises:
            AuthenticationFailed: If user cannot be mapped
        """
        config = provider.configuration

        # Try service principal mapping first (CLIENT_ID_CLAIM)
        client_id_claim = config.get('CLIENT_ID_CLAIM', 'azp')
        client_id = token_payload.get(client_id_claim)

        if client_id:
            # Service principal - look up by AuthenticatorUser.uid
            try:
                auth_user = AuthenticatorUser.objects.select_related('user').get(
                    provider=provider,
                    uid=client_id
                )
                logger.debug(f"Mapped service principal {client_id} to user {auth_user.user.username}")
                return auth_user.user
            except AuthenticatorUser.DoesNotExist:
                logger.warning(f"Service principal {client_id} not found for provider {provider.name}")

        # Try user mapping (USERNAME_CLAIM)
        username_claim = config.get('USERNAME_CLAIM', 'email')
        username_value = token_payload.get(username_claim)

        if username_value:
            # User token - look up by AuthenticatorUser.uid
            try:
                auth_user = AuthenticatorUser.objects.select_related('user').get(
                    provider=provider,
                    uid=username_value
                )
                logger.debug(f"Mapped user claim {username_claim}={username_value} to user {auth_user.user.username}")
                return auth_user.user
            except AuthenticatorUser.DoesNotExist:
                logger.warning(
                    f"User with {username_claim}={username_value} not found for provider {provider.name}"
                )

        # Authentication failed - no user mapping found
        logger.error(f"Failed to map JWT claims to user for provider {provider.name}")
        raise AuthenticationFailed("Authentication failed")

    def authenticate_header(self, request):
        """
        Return WWW-Authenticate header value for 401 responses.

        Per RFC 6750, Bearer auth challenges should include realm and error descriptor.
        """
        return 'Bearer realm="api"'
