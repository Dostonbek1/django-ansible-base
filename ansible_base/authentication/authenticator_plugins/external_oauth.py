"""
External OAuth Authenticator Plugin

This plugin enables API authentication using OAuth tokens issued by external identity
providers (Entra ID, Keycloak, generic OIDC, etc.) via JWT validation against JWKS endpoints.

Key Features:
- JWT signature verification using provider's JWKS endpoint
- OIDC auto-discovery support
- Configurable claim mapping for user/service principal identification
- No browser-based OAuth flow (API-only, no social_core dependency)

See: ANSTRAT-1611 P1 - External OAuth Provider Configuration
"""

import json
import logging
import ssl
import urllib.request
from urllib.parse import urljoin

from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.utils.translation import gettext_lazy as _

from ansible_base.authentication.authenticator_plugins.base import AbstractAuthenticatorPlugin, BaseAuthenticatorConfiguration
from ansible_base.authentication.authenticator_plugins.oidc import JWTAlgorithmListFieldValidator
from ansible_base.lib.serializers.fields import BooleanField, CharField, IntegerField, ListField, URLField

logger = logging.getLogger('ansible_base.authentication.authenticator_plugins.external_oauth')


class ExternalOAuthConfiguration(BaseAuthenticatorConfiguration):
    """
    Configuration schema for External OAuth authenticator.

    Supports JWKS-based JWT validation for external OAuth/OIDC providers.
    """

    documentation_url = "https://access.redhat.com/documentation/en-us/red_hat_ansible_automation_platform/"

    # Core JWT validation fields
    ISSUER_URL = URLField(
        help_text=_(
            "Provider's issuer URL (must match the 'iss' claim in tokens). "
            "Example: https://login.microsoftonline.com/{tenant}/v2.0"
        ),
        allow_null=False,
        ui_field_label=_('Issuer URL'),
    )

    JWKS_URI = URLField(
        help_text=_(
            "Provider's JWKS endpoint for fetching public keys to verify JWT signatures. "
            "Required unless OIDC_ENDPOINT is provided (which auto-discovers this value). "
            "Example: https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
        ),
        required=False,
        allow_null=True,
        ui_field_label=_('JWKS URI'),
    )

    ALLOWED_ALGORITHMS = ListField(
        help_text=_(
            "Allowed JWT signing algorithms for token validation. "
            "Common values: RS256, RS384, RS512, ES256, ES384, ES512. "
            "Defaults to ['RS256'] if not specified."
        ),
        default=["RS256"],
        allow_null=False,
        allow_empty=False,
        validators=[JWTAlgorithmListFieldValidator()],
        ui_field_label=_('Allowed JWT Algorithms'),
    )

    AUDIENCE = CharField(
        help_text=_(
            "Expected 'aud' (audience) claim value in tokens. "
            "Strongly recommended for security - prevents tokens intended for other services from being accepted. "
            "Leave empty only if your provider does not set 'aud' (e.g., some client credentials flows)."
        ),
        required=False,
        allow_null=True,
        allow_blank=True,
        default="",
        ui_field_label=_('Audience'),
    )

    JWKS_CACHE_TIMEOUT = IntegerField(
        help_text=_(
            "Duration (in seconds) to cache JWKS keys. "
            "Minimum: 60 seconds. Default: 3600 seconds (1 hour). "
            "Lower values mean more frequent key fetches but faster key rotation detection."
        ),
        default=3600,
        allow_null=False,
        validators=[MinValueValidator(60)],
        ui_field_label=_('JWKS Cache Timeout'),
    )

    # Claim mapping fields
    USERNAME_CLAIM = CharField(
        help_text=_(
            "JWT claim key for user identification. "
            "Common values: 'email', 'sub', 'preferred_username', 'upn'. "
            "Used to map tokens to existing AAP users via AuthenticatorUser records."
        ),
        default="email",
        allow_null=False,
        ui_field_label=_('Username Claim'),
    )

    CLIENT_ID_CLAIM = CharField(
        help_text=_(
            "JWT claim key for service principal (application) identification. "
            "Common values: 'azp' (Entra ID), 'client_id' (generic OIDC). "
            "Used to map service principal tokens to AAP User accounts representing external applications."
        ),
        default="azp",
        allow_null=False,
        ui_field_label=_('Client ID Claim'),
    )

    GROUPS_CLAIM = CharField(
        help_text=_(
            "JWT claim key for extracting user/service principal group memberships. "
            "Used for RBAC mapping via authenticator maps. "
            "Common values: 'groups' (Entra ID), 'Group' (generic OIDC). "
            "If groups are not in the JWT, they may be fetched from USERINFO_URL."
        ),
        default="groups",
        allow_null=True,
        allow_blank=True,
        required=False,
        ui_field_label=_('Groups Claim'),
    )

    # Optional OIDC endpoints
    USERINFO_URL = URLField(
        help_text=_(
            "Provider's UserInfo endpoint for fetching additional user data after JWT validation. "
            "Auto-discovered from OIDC_ENDPOINT if not explicitly set. "
            "Fetched only when needed (e.g., for group claims not in JWT). "
            "Example: https://login.microsoftonline.com/{tenant}/openid/userinfo"
        ),
        required=False,
        allow_null=True,
        ui_field_label=_('UserInfo URL'),
    )

    OIDC_ENDPOINT = URLField(
        help_text=_(
            "Base URL for OIDC auto-discovery. "
            "When provided, appends '/.well-known/openid-configuration' to fetch provider metadata "
            "and auto-populate JWKS_URI and USERINFO_URL. "
            "Either this or JWKS_URI must be provided. "
            "Example: https://login.microsoftonline.com/{tenant}/v2.0"
        ),
        required=False,
        allow_null=True,
        ui_field_label=_('OIDC Discovery Endpoint'),
    )

    VERIFY_SSL = BooleanField(
        help_text=_(
            "Verify SSL certificates for all provider requests (JWKS, OIDC discovery, UserInfo). "
            "Should be True in production. Set to False only for testing with self-signed certificates."
        ),
        default=True,
        allow_null=False,
        ui_field_label=_('Verify SSL Certificate'),
    )

    def validate(self, attrs):
        """
        Custom validation to ensure either JWKS_URI or OIDC_ENDPOINT is provided.
        If OIDC_ENDPOINT is provided, auto-populate JWKS_URI from discovery document.
        """
        attrs = super().validate(attrs)

        jwks_uri = attrs.get('JWKS_URI')
        oidc_endpoint = attrs.get('OIDC_ENDPOINT')

        # At least one must be provided
        if not jwks_uri and not oidc_endpoint:
            raise ValidationError({
                'JWKS_URI': _("Either JWKS_URI or OIDC_ENDPOINT must be provided."),
                'OIDC_ENDPOINT': _("Either JWKS_URI or OIDC_ENDPOINT must be provided."),
            })

        # If OIDC_ENDPOINT is provided, perform auto-discovery
        if oidc_endpoint:
            try:
                discovery_url = urljoin(oidc_endpoint.rstrip('/') + '/', '.well-known/openid-configuration')
                verify_ssl = attrs.get('VERIFY_SSL', True)

                # Fetch discovery document
                ssl_context = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()
                with urllib.request.urlopen(discovery_url, context=ssl_context, timeout=10) as response:
                    discovery_data = json.loads(response.read().decode('utf-8'))

                # Auto-populate JWKS_URI if not explicitly provided
                if not jwks_uri:
                    if 'jwks_uri' not in discovery_data:
                        raise ValidationError({
                            'OIDC_ENDPOINT': _("OIDC discovery document does not contain 'jwks_uri' field.")
                        })
                    attrs['JWKS_URI'] = discovery_data['jwks_uri']
                    logger.info(f"Auto-discovered JWKS_URI: {attrs['JWKS_URI']}")

                # Auto-populate USERINFO_URL if available and not explicitly set
                if not attrs.get('USERINFO_URL') and 'userinfo_endpoint' in discovery_data:
                    attrs['USERINFO_URL'] = discovery_data['userinfo_endpoint']
                    logger.info(f"Auto-discovered USERINFO_URL: {attrs['USERINFO_URL']}")

            except urllib.error.URLError as e:
                raise ValidationError({
                    'OIDC_ENDPOINT': _(
                        f"Failed to fetch OIDC discovery document from {discovery_url}: {str(e)}"
                    )
                })
            except json.JSONDecodeError:
                raise ValidationError({
                    'OIDC_ENDPOINT': _("OIDC discovery document is not valid JSON.")
                })
            except Exception as e:
                raise ValidationError({
                    'OIDC_ENDPOINT': _(f"Unexpected error during OIDC discovery: {str(e)}")
                })

        return attrs


class AuthenticatorPlugin(AbstractAuthenticatorPlugin):
    """
    External OAuth Authenticator Plugin

    Validates incoming API Bearer tokens (JWTs) against external OAuth/OIDC providers.
    No browser-based OAuth flow - this is API-only authentication.
    """

    configuration_class = ExternalOAuthConfiguration
    type = "external_oauth"
    category = "api_auth"  # New category for API-only token validation (not shown on login page)
    logger = logger
    configuration_encrypted_fields = []  # No secrets in this config (JWKS keys are public)

    def get_login_url(self, authenticator):
        """
        API-only authenticators don't have login URLs.
        Returns None to indicate this authenticator is not for browser-based login.
        """
        return None

    def get_default_attributes(self):
        """
        Return default attributes available for authenticator maps.
        These can be extracted from JWT claims or UserInfo endpoint.
        """
        return [
            'sub',  # Subject (user/service principal identifier)
            'email',
            'preferred_username',
            'name',
            'given_name',
            'family_name',
            'groups',  # Group memberships for RBAC
            'azp',  # Authorized party (client ID for service principals)
            'client_id',  # Alternative client ID claim
        ]
