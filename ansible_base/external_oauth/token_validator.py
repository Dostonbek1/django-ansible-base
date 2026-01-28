"""
External OAuth Token Validator

This module provides token validation logic for external OAuth tokens.
Supports:
- JWT tokens validated locally using JWKS
- Opaque tokens validated via introspection endpoint
"""
import logging
import ssl
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from urllib.request import urlopen

import jwt
import requests
from django.core.cache import cache
from jwt import PyJWKClient
from jwt.exceptions import PyJWTError

from ansible_base.external_oauth.models import ExternalOAuthProvider


class InsecurePyJWKClient(PyJWKClient):
    """PyJWKClient that skips SSL verification (for development/testing)."""
    
    def fetch_data(self) -> Any:
        """Fetch JWKS data with SSL verification disabled."""
        import json
        
        # Create unverified SSL context
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        with urlopen(self.uri, context=ssl_context, timeout=self.timeout) as response:
            return json.load(response)

logger = logging.getLogger('ansible_base.external_oauth.token_validator')


@dataclass
class TokenValidationResult:
    """Result of token validation."""
    valid: bool
    claims: Dict[str, Any]
    provider: Optional[ExternalOAuthProvider]
    error: Optional[str] = None
    is_user_token: bool = True  # False for service principal tokens


class TokenValidationError(Exception):
    """Base exception for token validation errors."""
    pass


class InvalidTokenError(TokenValidationError):
    """Token is invalid (malformed, expired, bad signature, etc.)."""
    pass


class ProviderUnavailableError(TokenValidationError):
    """External provider is unavailable."""
    pass


class ExternalOAuthTokenValidator:
    """
    Validates OAuth tokens from external providers.
    
    This validator supports:
    1. JWT tokens - validated locally using JWKS from the provider
    2. Opaque tokens - validated via the provider's introspection endpoint
    """
    
    JWKS_CACHE_PREFIX = 'external_oauth_jwks_'
    
    def __init__(self):
        self._jwk_clients: Dict[int, PyJWKClient] = {}
    
    def validate_token(self, token: str) -> TokenValidationResult:
        """
        Validate an external OAuth token.
        
        Args:
            token: The Bearer token to validate
            
        Returns:
            TokenValidationResult with validation status and claims
            
        Raises:
            InvalidTokenError: If the token is invalid
            ProviderUnavailableError: If no provider can validate the token
        """
        # Try to decode as JWT first to extract issuer
        issuer = self._extract_issuer(token)
        
        if issuer:
            # Find provider by issuer
            provider = self._find_provider_by_issuer(issuer)
            if provider:
                return self._validate_jwt_token(token, provider)
        
        # If we couldn't determine issuer or no provider matched,
        # try each enabled provider
        providers = ExternalOAuthProvider.objects.filter(enabled=True)
        
        for provider in providers:
            try:
                if provider.jwks_uri:
                    result = self._validate_jwt_token(token, provider)
                    if result.valid:
                        return result
                elif provider.introspection_url:
                    result = self._validate_opaque_token(token, provider)
                    if result.valid:
                        return result
            except TokenValidationError:
                continue
        
        # No provider could validate the token
        return TokenValidationResult(
            valid=False,
            claims={},
            provider=None,
            error="No configured provider could validate this token"
        )
    
    def _extract_issuer(self, token: str) -> Optional[str]:
        """
        Extract the issuer from a JWT token without full validation.
        """
        try:
            # Decode without verification to get claims
            unverified = jwt.decode(token, options={"verify_signature": False})
            return unverified.get('iss')
        except PyJWTError:
            return None
    
    def _find_provider_by_issuer(self, issuer: str) -> Optional[ExternalOAuthProvider]:
        """Find an enabled provider matching the given issuer."""
        try:
            return ExternalOAuthProvider.objects.get(issuer=issuer, enabled=True)
        except ExternalOAuthProvider.DoesNotExist:
            return None
    
    def _validate_jwt_token(
        self, 
        token: str, 
        provider: ExternalOAuthProvider
    ) -> TokenValidationResult:
        """
        Validate a JWT token using the provider's JWKS.
        """
        if not provider.jwks_uri:
            raise InvalidTokenError("Provider has no JWKS URI configured")
        
        try:
            # Get or create JWK client for this provider
            jwk_client = self._get_jwk_client(provider)
            
            # Get the signing key
            signing_key = jwk_client.get_signing_key_from_jwt(token)
            
            # Build decode options
            decode_options = {
                'verify_signature': True,
                'verify_exp': True,
                'verify_iat': True,
                'verify_aud': bool(provider.expected_audience),
                'require': ['exp', 'iat', 'iss'],
            }
            
            # Build decode kwargs
            decode_kwargs = {
                'key': signing_key.key,
                'algorithms': provider.get_jwt_algorithms(),
                'options': decode_options,
            }
            
            # Add audience if configured
            if provider.expected_audience:
                decode_kwargs['audience'] = provider.get_expected_audiences()
            
            # Add issuer verification
            decode_kwargs['issuer'] = provider.issuer
            
            # Decode and verify
            claims = jwt.decode(token, **decode_kwargs)
            
            # Determine if this is a user token or service principal token
            is_user_token = self._is_user_token(claims, provider)
            
            logger.info(
                f"Successfully validated JWT token from provider {provider.name} "
                f"(user_token={is_user_token})"
            )
            
            return TokenValidationResult(
                valid=True,
                claims=claims,
                provider=provider,
                is_user_token=is_user_token
            )
            
        except jwt.ExpiredSignatureError:
            logger.warning(f"Token expired for provider {provider.name}")
            return TokenValidationResult(
                valid=False,
                claims={},
                provider=provider,
                error="Token has expired"
            )
        except jwt.InvalidAudienceError:
            logger.warning(f"Invalid audience for provider {provider.name}")
            return TokenValidationResult(
                valid=False,
                claims={},
                provider=provider,
                error="Invalid token audience"
            )
        except jwt.InvalidIssuerError:
            logger.warning(f"Invalid issuer for provider {provider.name}")
            return TokenValidationResult(
                valid=False,
                claims={},
                provider=provider,
                error="Invalid token issuer"
            )
        except PyJWTError as e:
            logger.warning(f"JWT validation failed for provider {provider.name}: {e}")
            return TokenValidationResult(
                valid=False,
                claims={},
                provider=provider,
                error=f"Token validation failed: {str(e)}"
            )
        except requests.RequestException as e:
            logger.error(f"Failed to fetch JWKS from provider {provider.name}: {e}")
            raise ProviderUnavailableError(f"Failed to fetch JWKS: {e}")
    
    def _validate_opaque_token(
        self, 
        token: str, 
        provider: ExternalOAuthProvider
    ) -> TokenValidationResult:
        """
        Validate an opaque token using the provider's introspection endpoint.
        """
        if not provider.introspection_url:
            raise InvalidTokenError("Provider has no introspection URL configured")
        
        try:
            # Build introspection request
            data = {'token': token}
            
            # Add client credentials if configured
            auth = None
            if provider.client_id and provider.client_secret:
                auth = (provider.client_id, provider.get_client_secret())
            
            # Make introspection request
            response = requests.post(
                provider.introspection_url,
                data=data,
                auth=auth,
                verify=provider.verify_ssl,
                timeout=10
            )
            response.raise_for_status()
            
            result = response.json()
            
            # Check if token is active
            if not result.get('active', False):
                logger.warning(f"Token introspection returned inactive for provider {provider.name}")
                return TokenValidationResult(
                    valid=False,
                    claims={},
                    provider=provider,
                    error="Token is not active"
                )
            
            # Determine if this is a user token or service principal token
            is_user_token = self._is_user_token(result, provider)
            
            logger.info(
                f"Successfully validated opaque token from provider {provider.name} "
                f"(user_token={is_user_token})"
            )
            
            return TokenValidationResult(
                valid=True,
                claims=result,
                provider=provider,
                is_user_token=is_user_token
            )
            
        except requests.RequestException as e:
            logger.error(f"Introspection failed for provider {provider.name}: {e}")
            raise ProviderUnavailableError(f"Introspection failed: {e}")
    
    def _get_jwk_client(self, provider: ExternalOAuthProvider) -> PyJWKClient:
        """
        Get or create a JWK client for the given provider.
        
        JWK clients are cached per provider, and the JWKS keys are cached
        according to the provider's cache timeout setting.
        """
        if provider.pk not in self._jwk_clients:
            # Use InsecurePyJWKClient if SSL verification is disabled
            if provider.verify_ssl:
                client_class = PyJWKClient
            else:
                client_class = InsecurePyJWKClient
            
            self._jwk_clients[provider.pk] = client_class(
                provider.jwks_uri,
                cache_jwk_set=True,
                lifespan=provider.jwks_cache_timeout
            )
        return self._jwk_clients[provider.pk]
    
    def _is_user_token(self, claims: Dict[str, Any], provider: ExternalOAuthProvider) -> bool:
        """
        Determine if a token represents a user or a service principal.
        
        Service principal tokens typically:
        - Have no 'sub' claim or 'sub' equals the client_id
        - Have specific claims indicating app-only authentication
        
        This logic may need customization based on the identity provider.
        """
        # Get the user claim value
        user_claim = claims.get(provider.user_claim)
        
        # Get the client ID from claims
        client_id = claims.get(provider.client_id_claim) or claims.get('client_id')
        
        # Azure AD / Entra ID specific: check for 'idtyp' claim
        if claims.get('idtyp') == 'app':
            return False
        
        # If sub equals azp/client_id, it's likely a service principal
        sub = claims.get('sub')
        if sub and client_id and sub == client_id:
            return False
        
        # If there's no user-identifying claim, treat as service principal
        if not user_claim:
            return False
        
        return True


# Global validator instance
_validator = None


def get_token_validator() -> ExternalOAuthTokenValidator:
    """Get the global token validator instance."""
    global _validator
    if _validator is None:
        _validator = ExternalOAuthTokenValidator()
    return _validator
