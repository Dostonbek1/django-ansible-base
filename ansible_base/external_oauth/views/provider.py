"""
Views for External OAuth Provider management.
"""
import logging

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response

from ansible_base.external_oauth.models import ExternalOAuthProvider
from ansible_base.external_oauth.serializers.provider import (
    ExternalOAuthProviderListSerializer,
    ExternalOAuthProviderSerializer,
)

logger = logging.getLogger('ansible_base.external_oauth.views.provider')


class ExternalOAuthProviderViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing External OAuth Providers.
    
    Provides CRUD operations for configuring external identity providers
    that can be used to validate OAuth tokens for API authentication.
    
    Only administrators can manage providers.
    """
    
    queryset = ExternalOAuthProvider.objects.all()
    serializer_class = ExternalOAuthProviderSerializer
    permission_classes = [IsAdminUser]
    
    def get_serializer_class(self):
        if self.action == 'list':
            return ExternalOAuthProviderListSerializer
        return ExternalOAuthProviderSerializer
    
    @action(detail=True, methods=['post'])
    def test_connection(self, request, pk=None):
        """
        Test the connection to the OAuth provider.
        
        Attempts to fetch the JWKS or call the introspection endpoint
        to verify the provider is properly configured and accessible.
        """
        provider = self.get_object()
        errors = []
        successes = []
        
        # Test JWKS endpoint if configured
        if provider.jwks_uri:
            try:
                import requests
                response = requests.get(
                    provider.jwks_uri,
                    verify=provider.verify_ssl,
                    timeout=10
                )
                response.raise_for_status()
                data = response.json()
                
                if 'keys' in data:
                    key_count = len(data['keys'])
                    successes.append(f"JWKS endpoint returned {key_count} key(s)")
                else:
                    errors.append("JWKS endpoint response missing 'keys' field")
                    
            except requests.RequestException as e:
                errors.append(f"Failed to fetch JWKS: {str(e)}")
        
        # Test introspection endpoint if configured (just check it's reachable)
        if provider.introspection_url:
            try:
                import requests
                # Just do a HEAD request to check it's reachable
                response = requests.head(
                    provider.introspection_url,
                    verify=provider.verify_ssl,
                    timeout=10
                )
                # 401/405 are acceptable - endpoint exists but needs auth/POST
                if response.status_code in [200, 401, 405, 400]:
                    successes.append("Introspection endpoint is reachable")
                else:
                    errors.append(
                        f"Introspection endpoint returned unexpected status: "
                        f"{response.status_code}"
                    )
            except requests.RequestException as e:
                errors.append(f"Failed to reach introspection endpoint: {str(e)}")
        
        # Test OIDC discovery if issuer looks like OIDC endpoint
        if provider.issuer and not provider.jwks_uri:
            try:
                import requests
                discovery_url = f"{provider.issuer.rstrip('/')}/.well-known/openid-configuration"
                response = requests.get(
                    discovery_url,
                    verify=provider.verify_ssl,
                    timeout=10
                )
                response.raise_for_status()
                config = response.json()
                
                if 'jwks_uri' in config:
                    successes.append(
                        f"OIDC discovery found, JWKS URI: {config['jwks_uri']}"
                    )
                else:
                    successes.append("OIDC discovery endpoint is accessible")
                    
            except requests.RequestException as e:
                # This is optional, don't report as error
                pass
        
        if not errors:
            return Response({
                'status': 'success',
                'message': 'Provider connection test passed',
                'details': successes
            })
        else:
            return Response({
                'status': 'error' if not successes else 'partial',
                'message': 'Provider connection test completed with issues',
                'successes': successes,
                'errors': errors
            }, status=status.HTTP_400_BAD_REQUEST if not successes else status.HTTP_200_OK)
