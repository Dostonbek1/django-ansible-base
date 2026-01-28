"""
Views for External Application management.
"""
import logging

from rest_framework import viewsets
from rest_framework.permissions import IsAdminUser

from ansible_base.external_oauth.models import ExternalApplication, ExternalApplicationRoleAssignment
from ansible_base.external_oauth.serializers.application import (
    ExternalApplicationListSerializer,
    ExternalApplicationRoleAssignmentSerializer,
    ExternalApplicationSerializer,
)

logger = logging.getLogger('ansible_base.external_oauth.views.application')


class ExternalApplicationViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing External Applications.
    
    Provides CRUD operations for registering external applications that
    can authenticate to AAP using OAuth tokens from external providers.
    
    Only administrators can manage applications.
    """
    
    queryset = ExternalApplication.objects.select_related('provider').prefetch_related(
        'role_assignments'
    )
    serializer_class = ExternalApplicationSerializer
    permission_classes = [IsAdminUser]
    
    def get_serializer_class(self):
        if self.action == 'list':
            return ExternalApplicationListSerializer
        return ExternalApplicationSerializer
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filter by provider if specified
        provider_id = self.request.query_params.get('provider')
        if provider_id:
            queryset = queryset.filter(provider_id=provider_id)
        
        # Filter by enabled status if specified
        enabled = self.request.query_params.get('enabled')
        if enabled is not None:
            queryset = queryset.filter(enabled=enabled.lower() == 'true')
        
        return queryset


class ExternalApplicationRoleAssignmentViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing External Application Role Assignments.
    
    Provides CRUD operations for assigning RBAC roles to external applications.
    
    Only administrators can manage role assignments.
    """
    
    queryset = ExternalApplicationRoleAssignment.objects.select_related('application')
    serializer_class = ExternalApplicationRoleAssignmentSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filter by application if specified
        application_id = self.request.query_params.get('application')
        if application_id:
            queryset = queryset.filter(application_id=application_id)
        
        return queryset
