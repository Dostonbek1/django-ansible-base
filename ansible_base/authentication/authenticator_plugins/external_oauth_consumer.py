"""
External OAuth Consumer Authenticator Plugin

This plugin validates OAuth/OIDC tokens issued by external identity providers
(such as Entra ID, Ping Federate, Keycloak, or other OIDC-compliant providers)
for API authentication.

Unlike the OIDC plugin which handles browser-based SSO login flows, this plugin
validates Bearer tokens sent directly to API endpoints.

See SDP ANSTRAT-1611 for design details.
"""

import logging
from typing import Any

import jwt
import requests
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.utils.translation import gettext_lazy as _
from jwt import PyJWKClient
from jwt.algorithms import get_default_algorithms
from jwt.exceptions import PyJWTError

from ansible_base.authentication.authenticator_plugins.base import (
    AbstractAuthenticatorPlugin,
    BaseAuthenticatorConfiguration,
)
from ansible_base.lib.serializers.fields import (
    BooleanField,
    CharField,
    IntegerField,
    ListField,
    URLField,
)

logger = logging.getLogger('ansible_base.authentication.authenticator_plugins.external_oauth_consumer')

DEFAULT_ALGORITHMS = get_default_algorithms()


class JWTAlgorithmListFieldValidator:
    """Validator to ensure JWT algorithms are in the allowed list."""

    allowed_values = list(DEFAULT_ALGORITHMS.keys())

    def __call__(self, value):
        if not all(item in self.allowed_values for item in value):
            raise ValidationError(
                _('%(value)s contains items not in the allowed list: %(allowed_values)s'),
                params={'value': value, 'allowed_values': self.allowed_values},
            )


class InsecurePyJWKClient(PyJWKClient):
    """
    A PyJWKClient that optionally disables SSL verification.
    Used for development environments with self-signed certificates.
    """

    def __init__(self, uri: str, verify_ssl: bool = True, **kwargs):
        super().__init__(uri, **kwargs)
        self._verify_ssl = verify_ssl

    def _fetch_jwk_set(self):
        """Override to allow insecure connections when verify_ssl is False."""
        import urllib.request
        import ssl

        if not self._verify_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(self.uri, context=context, timeout=self.timeout) as response:
                return response.read().decode("utf-8")
        return super()._fetch_jwk_set()


class ExternalOAuthConsumerConfiguration(BaseAuthenticatorConfiguration):
    """Configuration schema for the external OAuth consumer authenticator plugin."""

    documentation_url = "https://docs.ansible.com/aap/external-oauth"

    # =========================
    # Provider Endpoints
    # =========================

    ISSUER_URL = URLField(
        help_text=_(
            "The issuer URL (iss claim) of the OAuth/OIDC provider. "
            "For Entra ID: https://login.microsoftonline.com/{tenant-id}/v2.0"
        ),
        allow_null=False,
        ui_field_label=_('Issuer URL'),
    )

    JWKS_URI = URLField(
        help_text=_(
            "URL to retrieve the provider's public keys (JWKS) for JWT signature verification. "
            "Required for JWT token validation."
        ),
        required=False,
        allow_null=True,
        ui_field_label=_('JWKS URI'),
    )

    INTROSPECTION_URL = URLField(
        help_text=_(
            "Token introspection endpoint URL for validating opaque tokens. "
            "Required if using opaque (non-JWT) tokens."
        ),
        required=False,
        allow_null=True,
        ui_field_label=_('Introspection Endpoint'),
    )

    USERINFO_URL = URLField(
        help_text=_("UserInfo endpoint URL (for OIDC providers). Optional."),
        required=False,
        allow_null=True,
        ui_field_label=_('UserInfo Endpoint'),
    )

    # =========================
    # Client Credentials (for introspection)
    # =========================

    CLIENT_ID = CharField(
        help_text=_("Client ID for introspection endpoint authentication."),
        required=False,
        allow_null=True,
        ui_field_label=_('Client ID'),
    )

    CLIENT_SECRET = CharField(
        help_text=_("Client secret for introspection endpoint authentication."),
        required=False,
        allow_null=True,
        ui_field_label=_('Client Secret'),
    )

    # =========================
    # Token Validation Settings
    # =========================

    EXPECTED_AUDIENCES = ListField(
        help_text=_(
            "List of acceptable audience values (aud claim). "
            "Leave empty to skip audience validation."
        ),
        default=list,
        required=False,
        allow_null=True,
        ui_field_label=_('Expected Audiences'),
    )

    ALLOWED_ALGORITHMS = ListField(
        help_text=_("Allowed JWT signing algorithms (e.g., RS256, ES256)."),
        default=["RS256"],
        allow_null=True,
        validators=[JWTAlgorithmListFieldValidator()],
        ui_field_label=_('Allowed Algorithms'),
    )

    JWKS_CACHE_TIMEOUT = IntegerField(
        help_text=_("How long to cache JWKS keys in seconds."),
        default=3600,
        allow_null=True,
        validators=[MinValueValidator(60)],
        ui_field_label=_('JWKS Cache Timeout'),
    )

    VERIFY_SSL = BooleanField(
        help_text=_("Verify TLS certificates when contacting provider endpoints."),
        default=True,
        allow_null=False,
        ui_field_label=_('Verify SSL'),
    )

    # =========================
    # Claim Mapping
    # =========================

    USERNAME_CLAIM = CharField(
        help_text=_(
            "JWT claim to use for mapping to AAP users. "
            "Common values: email, preferred_username, sub"
        ),
        default="email",
        allow_null=True,
        ui_field_label=_('Username Claim'),
    )

    CLIENT_ID_CLAIM = CharField(
        help_text=_(
            "JWT claim containing the service principal/application client ID. "
            "Common values: azp, client_id"
        ),
        default="azp",
        allow_null=True,
        ui_field_label=_('Client ID Claim'),
    )


class AuthenticatorPlugin(AbstractAuthenticatorPlugin):
    """
    External OAuth Consumer authenticator plugin.

    Validates OAuth/OIDC tokens from external identity providers for API access.
    This is a new category of authenticator (api_auth) that doesn't use browser flows.
    """

    configuration_class = ExternalOAuthConsumerConfiguration
    type = "external_oauth_consumer"
    category = "api_auth"
    logger = logger
    configuration_encrypted_fields = ['CLIENT_SECRET']

    # Cache for JWK clients per JWKS URI
    _jwk_clients: dict = {}

    def __init__(self, database_instance=None, *args, **kwargs):
        super().__init__(database_instance, *args, **kwargs)
        self._settings = {}

    def setting(self, name: str, default: Any = None) -> Any:
        """Get a configuration setting value."""
        if self.database_instance and self.database_instance.configuration:
            return self.database_instance.configuration.get(name, default)
        return default

    def validate_token(self, token: str) -> dict | None:
        """
        Validate an external OAuth token and return claims if valid.

        Args:
            token: The Bearer token to validate

        Returns:
            dict: Token claims if valid
            None: If validation fails
        """
        if self._is_jwt(token):
            return self._validate_jwt(token)
        return self._validate_via_introspection(token)

    def _is_jwt(self, token: str) -> bool:
        """Check if token appears to be a JWT (has 3 dot-separated parts)."""
        return len(token.split('.')) == 3

    def _validate_jwt(self, token: str) -> dict | None:
        """Validate JWT signature and claims using JWKS."""
        jwks_uri = self.setting('JWKS_URI')
        if not jwks_uri:
            self.logger.error("JWKS_URI not configured for JWT validation")
            return None

        try:
            # Get signing key
            signing_key = self._get_signing_key(token, jwks_uri)
            if not signing_key:
                return None

            # Build decode options
            decode_options = {
                'verify_exp': True,
                'verify_iat': True,
                'verify_iss': True,
            }

            # Handle audience validation
            expected_audiences = self.setting('EXPECTED_AUDIENCES')
            if expected_audiences:
                decode_options['verify_aud'] = True
            else:
                decode_options['verify_aud'] = False

            # Build decode kwargs
            decode_kwargs = {
                'key': signing_key.key,
                'algorithms': self.setting('ALLOWED_ALGORITHMS') or ['RS256'],
                'options': decode_options,
                'issuer': self.setting('ISSUER_URL'),
            }

            # Add audience if configured
            if expected_audiences:
                decode_kwargs['audience'] = expected_audiences

            # Decode and verify
            claims = jwt.decode(token, **decode_kwargs)
            return claims

        except jwt.ExpiredSignatureError:
            self.logger.info("Token has expired")
            return None
        except jwt.InvalidAudienceError:
            self.logger.info("Token audience mismatch")
            return None
        except jwt.InvalidIssuerError:
            self.logger.info("Token issuer mismatch")
            return None
        except PyJWTError as e:
            self.logger.warning(f"JWT validation failed: {e}")
            return None

    def _get_signing_key(self, token: str, jwks_uri: str):
        """Get signing key from JWKS with caching."""
        cache_timeout = self.setting('JWKS_CACHE_TIMEOUT') or 3600
        verify_ssl = self.setting('VERIFY_SSL')
        if verify_ssl is None:
            verify_ssl = True

        # Get or create JWK client
        jwk_client = self._get_or_create_jwks_client(jwks_uri, cache_timeout, verify_ssl)

        try:
            return jwk_client.get_signing_key_from_jwt(token)
        except jwt.PyJWKClientError as e:
            self.logger.warning(f"Failed to get signing key: {e}")
            # Try with refreshed keys on failure
            return self._refresh_and_get_signing_key(token, jwks_uri, cache_timeout, verify_ssl)

    def _get_or_create_jwks_client(self, jwks_uri: str, cache_timeout: int, verify_ssl: bool):
        """Get or create a PyJWKClient with cached keys."""
        cache_key = f"{jwks_uri}:{verify_ssl}"

        if cache_key not in self._jwk_clients:
            if verify_ssl:
                self._jwk_clients[cache_key] = PyJWKClient(
                    jwks_uri,
                    cache_jwk_set=True,
                    lifespan=cache_timeout,
                )
            else:
                self._jwk_clients[cache_key] = InsecurePyJWKClient(
                    jwks_uri,
                    verify_ssl=False,
                    cache_jwk_set=True,
                    lifespan=cache_timeout,
                )

        return self._jwk_clients[cache_key]

    def _refresh_and_get_signing_key(self, token: str, jwks_uri: str, cache_timeout: int, verify_ssl: bool):
        """Refresh JWKS and retry getting signing key."""
        try:
            # Create new client without cache
            if verify_ssl:
                jwks_client = PyJWKClient(jwks_uri, cache_jwk_set=False)
            else:
                jwks_client = InsecurePyJWKClient(jwks_uri, verify_ssl=False, cache_jwk_set=False)

            return jwks_client.get_signing_key_from_jwt(token)
        except Exception as e:
            self.logger.error(f"Failed to refresh JWKS: {e}")
            return None

    def _validate_via_introspection(self, token: str) -> dict | None:
        """Validate opaque token via introspection endpoint."""
        introspection_url = self.setting('INTROSPECTION_URL')
        if not introspection_url:
            self.logger.error("INTROSPECTION_URL not configured for opaque token")
            return None

        client_id = self.setting('CLIENT_ID')
        client_secret = self.setting('CLIENT_SECRET')

        if not client_id or not client_secret:
            self.logger.error("Client credentials required for introspection")
            return None

        verify_ssl = self.setting('VERIFY_SSL')
        if verify_ssl is None:
            verify_ssl = True

        try:
            response = requests.post(
                introspection_url,
                data={
                    'token': token,
                    'token_type_hint': 'access_token',
                },
                auth=(client_id, client_secret),
                verify=verify_ssl,
                timeout=10,
            )

            if not response.ok:
                self.logger.warning(f"Introspection request failed: {response.status_code}")
                return None

            data = response.json()

            # RFC 7662: active=true means token is valid
            if not data.get('active', False):
                self.logger.info("Token is not active (introspection)")
                return None

            # Validate issuer if configured
            expected_issuer = self.setting('ISSUER_URL')
            if expected_issuer and data.get('iss') != expected_issuer:
                self.logger.info("Token issuer mismatch (introspection)")
                return None

            return data

        except requests.RequestException as e:
            self.logger.error(f"Introspection request error: {e}")
            return None

    def resolve_identity(self, claims: dict):
        """
        Map validated token claims to an AAP user or service principal.

        Args:
            claims: The validated token claims

        Returns:
            User object if mapping succeeds, None if no match found
        """
        from ansible_base.authentication.models import AuthenticatorUser

        authenticator = self.database_instance
        if not authenticator:
            self.logger.error("No authenticator instance available for identity resolution")
            return None

        # Step 1: Try service principal mapping
        client_id_claim = self.setting('CLIENT_ID_CLAIM') or 'azp'
        client_id = claims.get(client_id_claim)

        if client_id:
            try:
                auth_user = AuthenticatorUser.objects.select_related('user').get(
                    provider=authenticator,
                    uid=client_id,
                    user__managed=True,
                )
                if auth_user.user.is_active:
                    self.logger.info(f"Token mapped to service principal: {auth_user.user.username}")
                    return auth_user.user
                else:
                    self.logger.info(f"Service principal {auth_user.user.username} is inactive")
            except AuthenticatorUser.DoesNotExist:
                pass  # Not a service principal, try user mapping

        # Step 2: Try user mapping
        username_claim = self.setting('USERNAME_CLAIM') or 'email'
        user_identifier = claims.get(username_claim)

        if not user_identifier:
            self.logger.warning(f"Token missing user identifier claim: {username_claim}")
            return None

        try:
            auth_user = AuthenticatorUser.objects.select_related('user').get(
                provider=authenticator,
                uid=user_identifier,
                user__managed=False,
            )
            if auth_user.user.is_active:
                self.logger.info(f"Token mapped to user: {auth_user.user.username}")
                return auth_user.user
            else:
                self.logger.info(f"User {auth_user.user.username} is inactive")
                return None
        except AuthenticatorUser.DoesNotExist:
            self.logger.info(f"No user found for identifier: {user_identifier}")
            return None

    def get_default_attributes(self):
        """Return default attributes available for authenticator maps."""
        return [
            'email',
            'preferred_username',
            'sub',
            'name',
            'given_name',
            'family_name',
            'azp',
            'client_id',
        ]

    def get_login_url(self, authenticator):
        """API auth plugins don't have login URLs."""
        return None
