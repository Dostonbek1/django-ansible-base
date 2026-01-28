"""
External Application Model

This model represents an external application that authenticates to AAP
using OAuth tokens from an external provider. Unlike user tokens, external
applications have their own RBAC permissions independent of any user.

This is used for service-to-service authentication where the calling
application acts on its own behalf, not on behalf of a user.
"""
import logging

from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _

from ansible_base.lib.abstract_models import CommonModel

logger = logging.getLogger('ansible_base.external_oauth.models.external_application')


class ExternalApplication(CommonModel):
    """
    An external application that can authenticate to AAP using external OAuth tokens.
    
    External applications are associated with a specific OAuth provider and are
    identified by their OAuth client ID from that provider. They have their own
    RBAC permissions independent of any user.
    """
    
    class Meta:
        app_label = 'dab_external_oauth'
        verbose_name = _('External Application')
        verbose_name_plural = _('External Applications')
        ordering = ['name']
        unique_together = [['provider', 'client_id']]
    
    # Basic identification
    name = models.CharField(
        max_length=255,
        help_text=_('A human-readable name for this external application.')
    )
    
    description = models.TextField(
        blank=True,
        null=True,
        help_text=_('A description of what this external application does.')
    )
    
    # Provider association
    provider = models.ForeignKey(
        'dab_external_oauth.ExternalOAuthProvider',
        on_delete=models.CASCADE,
        related_name='applications',
        help_text=_('The OAuth provider this application authenticates through.')
    )
    
    # Application identity (from the external provider)
    client_id = models.CharField(
        max_length=255,
        help_text=_('The OAuth client ID from the external provider. '
                    'This is used to match incoming tokens to this application.')
    )
    
    # Enabled status
    enabled = models.BooleanField(
        default=True,
        help_text=_('Whether this external application is allowed to authenticate.')
    )
    
    # Optional: Map to a specific user for audit/ownership purposes
    # Note: This is different from user-based authentication - this user doesn't
    # grant permissions, they're just the "owner" of the external application
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='owned_external_applications',
        help_text=_('Optional owner/administrator of this external application.')
    )
    
    # Audit fields
    last_used = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_('When this external application last authenticated.')
    )
    
    def update_last_used(self):
        """Update the last_used timestamp."""
        from django.utils import timezone
        self.last_used = timezone.now()
        self.save(update_fields=['last_used', 'modified'])
    
    def __str__(self):
        return f"{self.name} ({self.client_id})"


class ExternalApplicationRoleAssignment(CommonModel):
    """
    Assigns RBAC roles to external applications.
    
    This allows administrators to grant specific permissions to external
    applications independent of any user.
    
    Note: This is a simplified model. In production, this would integrate
    with the full RBAC system in django-ansible-base.
    """
    
    class Meta:
        app_label = 'dab_external_oauth'
        verbose_name = _('External Application Role Assignment')
        verbose_name_plural = _('External Application Role Assignments')
        unique_together = [['application', 'role_definition']]
    
    application = models.ForeignKey(
        ExternalApplication,
        on_delete=models.CASCADE,
        related_name='role_assignments',
        help_text=_('The external application receiving the role.')
    )
    
    # In production, this would be a ForeignKey to RoleDefinition
    # For POC, we'll use a CharField to store the role name
    role_definition = models.CharField(
        max_length=255,
        help_text=_('The role definition to assign (e.g., "Organization Admin", "Team Member").')
    )
    
    # Optional: Scope the role to a specific object
    # In production, this would use ContentType and object_id
    content_type = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text=_('Optional content type to scope the role (e.g., "organization", "team").')
    )
    
    object_id = models.PositiveIntegerField(
        blank=True,
        null=True,
        help_text=_('Optional object ID to scope the role.')
    )
    
    def __str__(self):
        scope = f" on {self.content_type}:{self.object_id}" if self.content_type else ""
        return f"{self.application.name} -> {self.role_definition}{scope}"
