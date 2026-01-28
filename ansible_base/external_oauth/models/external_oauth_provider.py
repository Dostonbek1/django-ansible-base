"""
External OAuth Provider Model

This model stores configuration for external OAuth/OIDC providers that can be
used to validate Bearer tokens for API authentication.

Supports:
- Azure AD / Entra ID
- Generic OIDC providers
- Custom OAuth 2.0 providers
"""
import logging
from typing import Optional

from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _

from ansible_base.lib.abstract_models import CommonModel
from ansible_base.lib.utils.encryption import ansible_encryption

logger = logging.getLogger('ansible_base.external_oauth.models.external_oauth_provider')


class ProviderType(models.TextChoices):
    """Supported provider types."""
    ENTRA_ID = 'entra_id', _('Azure AD / Entra ID')
    OIDC = 'oidc', _('Generic OIDC')
    OAUTH2 = 'oauth2', _('Custom OAuth 2.0')


class ExternalOAuthProvider(CommonModel):
    """
    Configuration for an external OAuth/OIDC provider.
    
    This model stores the necessary configuration to validate OAuth tokens
    issued by external identity providers.
    """
    
    class Meta:
        app_label = 'dab_external_oauth'
        verbose_name = _('External OAuth Provider')
        verbose_name_plural = _('External OAuth Providers')
        ordering = ['name']
    
    # Basic identification
    name = models.CharField(
        max_length=255,
        unique=True,
        help_text=_('A unique name for this provider configuration.')
    )
    
    provider_type = models.CharField(
        max_length=32,
        choices=ProviderType.choices,
        default=ProviderType.OIDC,
        help_text=_('The type of OAuth provider.')
    )
    
    enabled = models.BooleanField(
        default=True,
        help_text=_('Whether this provider is enabled for token validation.')
    )
    
    # Provider endpoints
    issuer = models.URLField(
        max_length=1024,
        help_text=_('The issuer URL (iss claim) for this provider. Used to match incoming tokens.')
    )
    
    authorization_url = models.URLField(
        max_length=1024,
        blank=True,
        null=True,
        help_text=_('Authorization endpoint URL (optional, for reference).')
    )
    
    token_url = models.URLField(
        max_length=1024,
        blank=True,
        null=True,
        help_text=_('Token endpoint URL (optional, for reference).')
    )
    
    userinfo_url = models.URLField(
        max_length=1024,
        blank=True,
        null=True,
        help_text=_('UserInfo endpoint URL for fetching additional user claims.')
    )
    
    jwks_uri = models.URLField(
        max_length=1024,
        blank=True,
        null=True,
        help_text=_('JWKS endpoint URL for retrieving public keys to validate JWT signatures.')
    )
    
    introspection_url = models.URLField(
        max_length=1024,
        blank=True,
        null=True,
        help_text=_('Token introspection endpoint URL for validating opaque tokens.')
    )
    
    # Client credentials (for introspection)
    client_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text=_('Client ID for token introspection (if required by provider).')
    )
    
    client_secret = models.CharField(
        max_length=1024,
        blank=True,
        null=True,
        help_text=_('Client secret for token introspection (stored encrypted).')
    )
    
    # Token validation settings
    expected_audience = models.CharField(
        max_length=1024,
        blank=True,
        null=True,
        help_text=_('Expected audience (aud) claim. Comma-separated for multiple values.')
    )
    
    jwt_algorithms = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of allowed JWT signing algorithms (e.g., ["RS256", "RS384"]).')
    )
    
    # Claim mapping
    user_claim = models.CharField(
        max_length=64,
        default='email',
        help_text=_('The claim to use for mapping to AAP users (e.g., email, sub, preferred_username).')
    )
    
    client_id_claim = models.CharField(
        max_length=64,
        default='azp',
        help_text=_('The claim to use for identifying service principal/application tokens (e.g., azp, client_id).')
    )
    
    # JWKS caching
    jwks_cache_timeout = models.IntegerField(
        default=3600,
        help_text=_('How long to cache JWKS keys (in seconds). Default: 1 hour.')
    )
    
    # SSL verification
    verify_ssl = models.BooleanField(
        default=True,
        help_text=_('Whether to verify SSL certificates when calling provider endpoints.')
    )
    
    def save(self, *args, **kwargs):
        """Encrypt client_secret before saving."""
        if self.client_secret and not self.client_secret.startswith('$encrypted$'):
            self.client_secret = ansible_encryption.encrypt_string(self.client_secret)
        super().save(*args, **kwargs)
    
    def get_client_secret(self) -> Optional[str]:
        """Decrypt and return the client secret."""
        if self.client_secret:
            return ansible_encryption.decrypt_string(self.client_secret)
        return None
    
    def get_expected_audiences(self) -> list:
        """Return expected audiences as a list."""
        if self.expected_audience:
            return [aud.strip() for aud in self.expected_audience.split(',')]
        return []
    
    def get_jwt_algorithms(self) -> list:
        """Return JWT algorithms, with sensible defaults."""
        if self.jwt_algorithms:
            return self.jwt_algorithms
        return ['RS256', 'RS384', 'RS512']
    
    def __str__(self):
        return f"{self.name} ({self.get_provider_type_display()})"
