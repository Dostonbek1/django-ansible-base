import json
import logging
import ssl
import urllib.request
from urllib.parse import urlparse, urlunparse

from django.core.validators import MinValueValidator
from django.utils.translation import gettext_lazy as _
from rest_framework.serializers import ValidationError

from ansible_base.authentication.authenticator_plugins.base import AbstractAuthenticatorPlugin, BaseAuthenticatorConfiguration
from ansible_base.authentication.authenticator_plugins.oidc import JWTAlgorithmListFieldValidator
from ansible_base.lib.serializers.fields import BooleanField, CharField, IntegerField, ListField, URLField

logger = logging.getLogger('ansible_base.authentication.authenticator_plugins.external_oauth')


class ExternalOAuthConfiguration(BaseAuthenticatorConfiguration):
    documentation_url = "https://openid.net/specs/openid-connect-discovery-1_0.html"

    ISSUER_URL = URLField(
        help_text=_("The OAuth provider's issuer URL. Must match the 'iss' claim in incoming JWTs."),
        allow_null=False,
        ui_field_label=_('Issuer URL'),
    )

    JWKS_URI = URLField(
        help_text=_(
            "The provider's JWKS endpoint for signature verification. "
            "Either JWKS_URI or OIDC_ENDPOINT must be provided. "
            "If OIDC_ENDPOINT is provided, this is auto-populated from the discovery document."
        ),
        required=False,
        allow_null=True,
        default="",
        ui_field_label=_('JWKS URI'),
    )

    ALLOWED_ALGORITHMS = ListField(
        help_text=_("Allowed JWT signing algorithms (e.g., RS256, ES256)."),
        default=["RS256"],
        allow_null=False,
        allow_empty=False,
        validators=[JWTAlgorithmListFieldValidator()],
        ui_field_label=_('Allowed JWT Algorithms'),
    )

    AUDIENCE = CharField(
        help_text=_(
            "Expected 'aud' claim value. Strongly recommended for security. "
            "When empty, audience validation is skipped."
        ),
        required=False,
        allow_blank=True,
        default="",
        ui_field_label=_('Expected Audience'),
    )

    JWKS_CACHE_TIMEOUT = IntegerField(
        help_text=_("JWKS cache duration in seconds."),
        default=3600,
        validators=[MinValueValidator(60)],
        ui_field_label=_('JWKS Cache Timeout (seconds)'),
    )

    USERNAME_CLAIM = CharField(
        help_text=_("JWT claim used for user identification (e.g., 'email', 'preferred_username', 'sub')."),
        default="email",
        ui_field_label=_('Username Claim'),
    )

    CLIENT_ID_CLAIM = CharField(
        help_text=_(
            "JWT claim used for service principal identification (e.g., 'azp', 'client_id'). "
            "When a token contains this claim but not the USERNAME_CLAIM, it is treated as a service principal token."
        ),
        required=False,
        allow_blank=True,
        default="azp",
        ui_field_label=_('Client ID Claim'),
    )

    USERINFO_URL = URLField(
        help_text=_(
            "URL to fetch additional user information after JWT validation. "
            "Used to retrieve supplementary claims (e.g., group memberships for authenticator maps)."
        ),
        required=False,
        allow_null=True,
        default="",
        ui_field_label=_('UserInfo URL'),
    )

    OIDC_ENDPOINT = URLField(
        help_text=_(
            "Base URL for OIDC auto-discovery. Appends /.well-known/openid-configuration to auto-populate JWKS_URI. "
            "Either JWKS_URI or OIDC_ENDPOINT must be provided. Fetched at save time only."
        ),
        required=False,
        allow_null=True,
        default="",
        ui_field_label=_('OIDC Discovery Endpoint'),
    )

    VERIFY_SSL = BooleanField(
        help_text=_("Verify the OAuth provider's SSL certificate for all outbound requests (JWKS, OIDC discovery, UserInfo)."),
        default=True,
        allow_null=False,
        ui_field_label=_('Verify SSL Certificate'),
    )

    def validate(self, attrs):
        attrs = super().validate(attrs)
        jwks_uri = attrs.get('JWKS_URI', '') or ''
        oidc_endpoint = attrs.get('OIDC_ENDPOINT', '') or ''

        if not jwks_uri and not oidc_endpoint:
            raise ValidationError({
                'JWKS_URI': _("Either JWKS_URI or OIDC_ENDPOINT must be provided."),
                'OIDC_ENDPOINT': _("Either JWKS_URI or OIDC_ENDPOINT must be provided."),
            })

        if oidc_endpoint and not jwks_uri:
            discovered_jwks_uri = self._discover_jwks_uri(oidc_endpoint, attrs.get('VERIFY_SSL', True))
            attrs['JWKS_URI'] = discovered_jwks_uri

        return attrs

    def _discover_jwks_uri(self, oidc_endpoint, verify_ssl):
        discovery_url = oidc_endpoint.rstrip('/') + '/.well-known/openid-configuration'
        try:
            ctx = None
            if not verify_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(discovery_url)
            req.add_header('Accept', 'application/json')
            with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                data = json.loads(response.read().decode('utf-8'))

            jwks_uri = data.get('jwks_uri')
            if not jwks_uri:
                raise ValidationError({
                    'OIDC_ENDPOINT': _("OIDC discovery document does not contain 'jwks_uri'."),
                })

            # The discovered jwks_uri often uses the provider's public hostname
            # (e.g. localhost:8443) which may not be reachable from the gateway
            # container. Rewrite it to use the OIDC_ENDPOINT's host/port so the
            # runtime JWKS fetch uses the internal network address.
            jwks_uri = self._rewrite_uri_host(jwks_uri, oidc_endpoint)
            return jwks_uri

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"OIDC auto-discovery failed for {discovery_url}: {e}")
            raise ValidationError({
                'OIDC_ENDPOINT': _(f"Failed to fetch OIDC discovery document: {e}"),
            })

    @staticmethod
    def _rewrite_uri_host(discovered_uri, oidc_endpoint):
        """Replace the scheme + host + port of discovered_uri with those from oidc_endpoint."""
        discovered = urlparse(discovered_uri)
        endpoint = urlparse(oidc_endpoint)
        return urlunparse((
            endpoint.scheme,
            endpoint.netloc,
            discovered.path,
            discovered.params,
            discovered.query,
            discovered.fragment,
        ))


class AuthenticatorPlugin(AbstractAuthenticatorPlugin):
    configuration_class = ExternalOAuthConfiguration
    type = "external_oauth"
    category = "api_auth"
    logger = logger
    configuration_encrypted_fields = []

    def get_login_url(self, authenticator):
        return None

    def get_default_attributes(self):
        return ["email", "preferred_username", "sub", "azp", "client_id"]
