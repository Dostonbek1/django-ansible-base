"""
URL configuration for External OAuth API.

Endpoints:
  - /identity_providers/                  - External identity provider configurations
  - /identity_provider_applications/      - Applications authenticating via external IdPs
  - /identity_provider_role_assignments/  - RBAC role assignments for IdP applications
"""
from rest_framework.routers import DefaultRouter

from ansible_base.external_oauth.views import (
    ExternalApplicationRoleAssignmentViewSet,
    ExternalApplicationViewSet,
    ExternalOAuthProviderViewSet,
)

router = DefaultRouter()
router.register(
    r'identity_providers',
    ExternalOAuthProviderViewSet,
    basename='identity-provider'
)
router.register(
    r'identity_provider_applications',
    ExternalApplicationViewSet,
    basename='identity-provider-application'
)
router.register(
    r'identity_provider_role_assignments',
    ExternalApplicationRoleAssignmentViewSet,
    basename='identity-provider-role-assignment'
)

urlpatterns = router.urls
