import json
import logging
import ssl
import urllib.request
from collections import namedtuple

import jwt
from django.conf import settings
from django.core.cache import cache
from django.utils.encoding import smart_str
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from ansible_base.authentication.models import Authenticator, AuthenticatorUser
from ansible_base.lib.logging import log_auth_event

logger = logging.getLogger('ansible_base.authentication.external_oauth')

ValidatedToken = namedtuple('ValidatedToken', ['payload', 'provider_name'])

JWKS_CACHE_KEY_PREFIX = 'external_oauth_jwks_'
JWKS_COOLDOWN_KEY_PREFIX = 'external_oauth_jwks_cooldown_'
JWKS_COOLDOWN_SECONDS = 30


class ExternalOAuthAuthentication(BaseAuthentication):
    """
    DRF authentication class that validates incoming Bearer tokens against
    configured external OAuth/OIDC providers via JWT signature verification,
    claims validation, and multi-provider routing.
    """

    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.lower().startswith('bearer '):
            return None

        token = auth_header.split(' ', 1)[1].strip()
        if not token:
            return None

        # Step 2: Decode JWT header + payload WITHOUT verification
        try:
            unverified_header = jwt.get_unverified_header(token)
            unverified_payload = jwt.decode(token, options={"verify_signature": False}, algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "EdDSA"])
        except jwt.exceptions.DecodeError:
            logger.debug("Token is not a valid JWT, skipping external OAuth authentication")
            return None

        # Step 3: Extract iss and aud from unverified payload
        issuer = unverified_payload.get('iss')
        if not issuer:
            return None

        # Skip AAP's own tokens (Workload Identity)
        aap_issuer = self._get_aap_issuer_url()
        if aap_issuer and issuer == aap_issuer:
            return None

        audience = unverified_payload.get('aud')
        if isinstance(audience, list) and len(audience) == 1:
            audience = audience[0]

        # Step 4: Find matching external_oauth authenticator
        authenticator = self._find_matching_provider(issuer, audience)
        if authenticator is None:
            return None

        # From this point on, we've matched a provider - errors should reject, not fallthrough
        config = authenticator.configuration
        provider_name = authenticator.name

        # Step 5: Fetch JWKS keys
        jwks_uri = config.get('JWKS_URI', '')
        cache_timeout = config.get('JWKS_CACHE_TIMEOUT', 3600)
        verify_ssl = config.get('VERIFY_SSL', True)
        allowed_algorithms = config.get('ALLOWED_ALGORITHMS', ['RS256'])
        expected_audience = config.get('AUDIENCE', '') or None

        signing_keys = self._get_jwks_keys(jwks_uri, cache_timeout, verify_ssl, provider_name)
        if not signing_keys:
            log_auth_event(
                f"External OAuth authentication failed: JWKS unavailable for provider '{provider_name}' (uri={jwks_uri})",
                logging.ERROR,
            )
            raise AuthenticationFailed("Authentication service unavailable")

        # Step 6: Verify JWT signature
        kid = unverified_header.get('kid')
        signing_key = self._find_signing_key(signing_keys, kid)
        if not signing_key:
            # Key rotation: try refreshing JWKS
            signing_keys = self._refresh_jwks_keys(jwks_uri, cache_timeout, verify_ssl, provider_name)
            if signing_keys:
                signing_key = self._find_signing_key(signing_keys, kid)

            if not signing_key:
                log_auth_event(
                    f"External OAuth authentication failed: no matching key (kid={kid}) for provider '{provider_name}'",
                    logging.WARNING,
                )
                raise AuthenticationFailed("Invalid token signature")

        # Step 7: Validate claims
        try:
            decode_options = {}
            if not expected_audience:
                decode_options['verify_aud'] = False

            payload = jwt.decode(
                token,
                key=signing_key,
                algorithms=allowed_algorithms,
                audience=expected_audience,
                issuer=config.get('ISSUER_URL', ''),
                options=decode_options,
            )
        except jwt.ExpiredSignatureError:
            log_auth_event(
                f"External OAuth authentication failed: expired token for provider '{provider_name}'",
                logging.DEBUG,
            )
            raise AuthenticationFailed("Token has expired")
        except jwt.InvalidAudienceError:
            log_auth_event(
                f"External OAuth authentication failed: audience mismatch for provider '{provider_name}' "
                f"(expected={expected_audience})",
                logging.WARNING,
            )
            raise AuthenticationFailed("Authentication failed")
        except jwt.InvalidIssuerError:
            log_auth_event(
                f"External OAuth authentication failed: issuer mismatch for provider '{provider_name}'",
                logging.WARNING,
            )
            raise AuthenticationFailed("Authentication failed")
        except jwt.InvalidSignatureError:
            # Retry with fresh keys (key rotation)
            signing_keys = self._refresh_jwks_keys(jwks_uri, cache_timeout, verify_ssl, provider_name)
            if signing_keys:
                signing_key = self._find_signing_key(signing_keys, kid)
                if signing_key:
                    try:
                        payload = jwt.decode(
                            token,
                            key=signing_key,
                            algorithms=allowed_algorithms,
                            audience=expected_audience,
                            issuer=config.get('ISSUER_URL', ''),
                            options=decode_options,
                        )
                    except jwt.PyJWTError:
                        log_auth_event(
                            f"External OAuth authentication failed: invalid signature after key refresh for provider '{provider_name}'",
                            logging.WARNING,
                        )
                        raise AuthenticationFailed("Invalid token signature")
                else:
                    raise AuthenticationFailed("Invalid token signature")
            else:
                raise AuthenticationFailed("Invalid token signature")
        except jwt.PyJWTError as e:
            log_auth_event(
                f"External OAuth authentication failed: JWT validation error for provider '{provider_name}': {type(e).__name__}",
                logging.WARNING,
            )
            raise AuthenticationFailed("Authentication failed")

        # Step 8: Fetch UserInfo if configured (supplementary claims)
        userinfo_url = config.get('USERINFO_URL', '') or ''
        if userinfo_url:
            userinfo = self._fetch_userinfo(userinfo_url, token, verify_ssl, provider_name)
            if userinfo:
                payload.update(userinfo)

        # Step 9: Resolve user
        user = self._resolve_user(payload, config, authenticator, provider_name)
        if user is None:
            log_auth_event(
                f"External OAuth authentication failed: user not found for provider '{provider_name}'",
                logging.WARNING,
            )
            raise AuthenticationFailed("Authentication failed")

        log_auth_event(
            smart_str(
                f"User {user.username} authenticated via external OAuth provider '{provider_name}' "
                f"using {request.method} to {request.path}"
            )
        )

        validated_token = ValidatedToken(payload=payload, provider_name=provider_name)
        return (user, validated_token)

    def authenticate_header(self, request):
        return 'Bearer realm="api"'

    # --- Provider lookup ---

    def _find_matching_provider(self, issuer, audience):
        """Find the external_oauth authenticator matching the token's iss (and aud for disambiguation)."""
        authenticators = Authenticator.objects.filter(
            enabled=True,
            category='api_auth',
            type='ansible_base.authentication.authenticator_plugins.external_oauth',
        )

        matches = []
        for auth in authenticators:
            config = auth.configuration
            if config.get('ISSUER_URL', '') == issuer:
                matches.append(auth)

        if len(matches) == 0:
            return None

        if len(matches) == 1:
            return matches[0]

        # Multiple providers share the same issuer - disambiguate by audience
        if audience:
            for auth in matches:
                config_audience = auth.configuration.get('AUDIENCE', '')
                if config_audience and config_audience == audience:
                    return auth

        # Fallback: return first match if no audience disambiguation succeeds
        return matches[0]

    # --- JWKS key management ---

    def _get_jwks_cache_key(self, jwks_uri):
        return f"{JWKS_CACHE_KEY_PREFIX}{jwks_uri}"

    def _get_jwks_cooldown_key(self, jwks_uri):
        return f"{JWKS_COOLDOWN_KEY_PREFIX}{jwks_uri}"

    def _get_jwks_keys(self, jwks_uri, cache_timeout, verify_ssl, provider_name):
        """Get JWKS keys from cache or fetch from provider."""
        cache_key = self._get_jwks_cache_key(jwks_uri)
        cached_jwks_json = cache.get(cache_key)
        if cached_jwks_json is not None:
            return self._parse_jwks_keys(cached_jwks_json, provider_name)

        return self._fetch_and_cache_jwks(jwks_uri, cache_timeout, verify_ssl, provider_name)

    def _refresh_jwks_keys(self, jwks_uri, cache_timeout, verify_ssl, provider_name):
        """Force-refresh JWKS keys, with cooldown to prevent excessive fetching."""
        cooldown_key = self._get_jwks_cooldown_key(jwks_uri)
        if cache.get(cooldown_key):
            cached_jwks_json = cache.get(self._get_jwks_cache_key(jwks_uri))
            if cached_jwks_json is not None:
                return self._parse_jwks_keys(cached_jwks_json, provider_name)
            return None

        cache.set(cooldown_key, True, JWKS_COOLDOWN_SECONDS)
        return self._fetch_and_cache_jwks(jwks_uri, cache_timeout, verify_ssl, provider_name)

    def _fetch_and_cache_jwks(self, jwks_uri, cache_timeout, verify_ssl, provider_name):
        """Fetch JWKS from the provider endpoint and cache the raw JSON."""
        try:
            ctx = None
            if not verify_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(jwks_uri)
            req.add_header('Accept', 'application/json')
            with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                jwks_json = response.read().decode('utf-8')

            jwks_data = json.loads(jwks_json)
            keys = jwks_data.get('keys', [])
            if not keys:
                logger.warning(f"JWKS response from {jwks_uri} contains no keys")
                return None

            # Cache the raw JSON string (serializable), not parsed key objects
            cache_key = self._get_jwks_cache_key(jwks_uri)
            cache.set(cache_key, jwks_json, cache_timeout)

            return self._parse_jwks_keys(jwks_json, provider_name)

        except Exception as e:
            logger.error(f"Failed to fetch JWKS from {jwks_uri} for provider '{provider_name}': {type(e).__name__}: {e}")
            cached_jwks_json = cache.get(self._get_jwks_cache_key(jwks_uri))
            if cached_jwks_json is not None:
                logger.info(f"Using cached JWKS keys for provider '{provider_name}'")
                return self._parse_jwks_keys(cached_jwks_json, provider_name)
            return None

    def _parse_jwks_keys(self, jwks_json, provider_name):
        """Parse raw JWKS JSON into a dict of {kid: key_object}."""
        jwks_data = json.loads(jwks_json)
        signing_keys = {}
        for key_data in jwks_data.get('keys', []):
            kid = key_data.get('kid', '')
            key_json = json.dumps(key_data)
            try:
                signing_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(key_json)
            except Exception:
                for algo_cls in [jwt.algorithms.ECAlgorithm, jwt.algorithms.OKPAlgorithm]:
                    try:
                        signing_keys[kid] = algo_cls.from_jwk(key_json)
                        break
                    except Exception:
                        continue
        return signing_keys or None

    def _find_signing_key(self, signing_keys, kid):
        """Find the signing key matching the JWT's kid header."""
        if kid and kid in signing_keys:
            return signing_keys[kid]
        # If no kid or kid not found, return first key (single-key providers)
        if signing_keys:
            return next(iter(signing_keys.values()))
        return None

    # --- UserInfo ---

    def _fetch_userinfo(self, userinfo_url, token, verify_ssl, provider_name):
        """Fetch supplementary user claims from the UserInfo endpoint."""
        try:
            ctx = None
            if not verify_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(userinfo_url)
            req.add_header('Authorization', f'Bearer {token}')
            req.add_header('Accept', 'application/json')
            with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                return json.loads(response.read().decode('utf-8'))

        except Exception as e:
            logger.warning(f"Failed to fetch UserInfo from {userinfo_url} for provider '{provider_name}': {e}")
            return None

    # --- User resolution ---

    def _resolve_user(self, payload, config, authenticator, provider_name):
        """
        Resolve the JWT payload to a local AAP user.

        1. Look up an existing AuthenticatorUser link for this provider (fast path).
        2. If none exists, find the user by claim value (username/email)
           and auto-create the AuthenticatorUser link.
        3. If no user exists at all and create_objects=True, create the user
           and the AuthenticatorUser link (JIT provisioning).

        Service principals must be pre-configured by administrators.
        """
        from django.contrib.auth import get_user_model

        User = get_user_model()

        username_claim = config.get('USERNAME_CLAIM', 'email')
        client_id_claim = config.get('CLIENT_ID_CLAIM', 'azp')

        uid = payload.get(username_claim, '')
        is_service_principal = False

        if not uid and client_id_claim:
            uid = payload.get(client_id_claim, '')
            is_service_principal = bool(uid)

        if not uid:
            logger.warning(
                f"External OAuth: no identifiable claim found in token for provider '{provider_name}' "
                f"(tried '{username_claim}' and '{client_id_claim}')"
            )
            return None

        # 1. Check for existing AuthenticatorUser link (fast path)
        try:
            auth_user = AuthenticatorUser.objects.select_related('user').get(
                provider=authenticator,
                uid=uid,
            )
            return auth_user.user
        except AuthenticatorUser.DoesNotExist:
            pass

        # 2. Service principals must be pre-configured -- no JIT
        if is_service_principal:
            logger.debug(
                f"External OAuth: no AuthenticatorUser for service principal in provider '{provider_name}'"
            )
            return None

        if not authenticator.create_objects:
            logger.debug(
                f"External OAuth: create_objects=False, skipping JIT for provider '{provider_name}'"
            )
            return None

        # 3. Try to find an existing AAP user by claim value
        user = self._find_existing_user(User, username_claim, uid, payload)

        # 4. No existing user -- create one
        if user is None:
            user = self._create_user(User, username_claim, uid, payload, provider_name)
            if user is None:
                return None

        # 5. Create the AuthenticatorUser link
        AuthenticatorUser.objects.create(
            user=user,
            provider=authenticator,
            uid=uid,
        )
        log_auth_event(
            f"External OAuth: auto-linked user '{user.username}' to provider '{provider_name}' (uid={uid})"
        )
        return user

    def _find_existing_user(self, User, claim_name, claim_value, payload):
        """Find an existing AAP user by matching the claim value against User fields."""
        lookup_strategies = []
        if claim_name in ('email',):
            lookup_strategies.append({'email__iexact': claim_value})
        if claim_name in ('preferred_username', 'sub', 'username'):
            lookup_strategies.append({'username__iexact': claim_value})

        lookup_strategies.extend([
            {'username__iexact': claim_value},
            {'email__iexact': claim_value},
        ])

        seen = set()
        for lookup in lookup_strategies:
            key = frozenset(lookup.items())
            if key in seen:
                continue
            seen.add(key)
            try:
                return User.objects.get(**lookup)
            except (User.DoesNotExist, User.MultipleObjectsReturned):
                continue
        return None

    def _create_user(self, User, username_claim, uid, payload, provider_name):
        """Create a new AAP user from JWT claims."""
        username = payload.get('preferred_username', '') or payload.get('sub', '') or uid
        email = payload.get('email', '')

        if not username:
            logger.warning(
                f"External OAuth: cannot determine username for new user from provider '{provider_name}'"
            )
            return None

        # Avoid collisions with existing usernames
        if User.objects.filter(username__iexact=username).exists():
            logger.warning(
                f"External OAuth: username '{username}' already taken, cannot create user for provider '{provider_name}'"
            )
            return None

        user = User.objects.create_user(
            username=username,
            email=email,
        )
        user.set_unusable_password()
        user.save(update_fields=['password'])
        log_auth_event(
            f"External OAuth: created user '{username}' from provider '{provider_name}'"
        )
        return user

    # --- Helpers ---

    def _get_aap_issuer_url(self):
        """Get AAP's own OIDC issuer URL to skip Workload Identity tokens."""
        oauth2_settings = getattr(settings, 'OAUTH2_PROVIDER', {})
        return oauth2_settings.get('OIDC_ISS_ENDPOINT', '')
