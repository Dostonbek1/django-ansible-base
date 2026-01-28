"""
External OAuth Authentication for Django REST Framework

This module provides a DRF authentication class that validates Bearer tokens
from external OAuth/OIDC providers and maps them to AAP users or external
applications.
"""
import logging
from typing import Optional, Tuple

from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.encoding import smart_str
from django.utils.translation import gettext_lazy as _
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from ansible_base.external_oauth.models import ExternalApplication, ExternalOAuthProvider
from ansible_base.external_oauth.token_validator import (
    ExternalOAuthTokenValidator,
    InvalidTokenError,
    ProviderUnavailableError,
    TokenValidationResult,
    get_token_validator,
)
from ansible_base.lib.logging import log_auth_event

logger = logging.getLogger('ansible_base.external_oauth.authentication')

User = get_user_model()


class ExternalOAuthUser:
    """
    A pseudo-user object representing an authenticated external application.
    
    This is used when the token represents a service principal rather than
    a human user. It provides enough of the User interface to work with
    DRF's permission system.
    """
    
    def __init__(self, application: ExternalApplication, claims: dict):
        self.application = application
        self.claims = claims
        self.pk = f"ext_app_{application.pk}"
        self.username = f"external_app:{application.name}"
        self.is_authenticated = True
        self.is_active = application.enabled
        self.is_superuser = False
        self.is_staff = False
        
        # Store roles for permission checking
        self._roles = list(application.role_assignments.values_list('role_definition', flat=True))
    
    @property
    def is_anonymous(self):
        return False
    
    def has_perm(self, perm, obj=None):
        """Check if the application has a specific permission."""
        # Simplified permission check - in production this would integrate
        # with the full RBAC system
        return perm in self._roles
    
    def has_perms(self, perm_list, obj=None):
        """Check if the application has all specified permissions."""
        return all(self.has_perm(perm, obj) for perm in perm_list)
    
    def __str__(self):
        return self.username


class ExternalOAuthAuthentication(BaseAuthentication):
    """
    DRF Authentication class for external OAuth tokens.
    
    This authentication class:
    1. Extracts Bearer tokens from the Authorization header
    2. Validates the token against configured external OAuth providers
    3. Maps user tokens to existing AAP users
    4. Maps service principal tokens to external applications
    5. Logs authentication events for audit purposes
    
    Usage:
        Add to REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES']:
        
        REST_FRAMEWORK = {
            'DEFAULT_AUTHENTICATION_CLASSES': [
                'ansible_base.external_oauth.authentication.ExternalOAuthAuthentication',
                # ... other authentication classes
            ],
        }
    """
    
    keyword = 'Bearer'
    
    def authenticate(self, request) -> Optional[Tuple]:
        """
        Authenticate the request using external OAuth token.
        
        Returns:
            Tuple of (user, token_info) if authentication succeeds
            None if this authentication method doesn't apply
            
        Raises:
            AuthenticationFailed if authentication fails
        """
        # Extract the Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header:
            return None
        
        # Check if it's a Bearer token
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != self.keyword.lower():
            return None
        
        token = parts[1]
        
        # Validate the token
        validator = get_token_validator()
        
        try:
            result = validator.validate_token(token)
        except ProviderUnavailableError as e:
            logger.error(f"External OAuth provider unavailable: {e}")
            # Don't fail authentication, let other authenticators try
            # This implements graceful degradation
            return None
        except InvalidTokenError as e:
            logger.warning(f"Invalid external OAuth token: {e}")
            raise AuthenticationFailed(_('Invalid token.'))
        
        if not result.valid:
            # Token validation failed, but it might be valid for another authenticator
            # (e.g., a locally-issued OAuth2 token)
            # Only raise if we're confident this was meant to be an external token
            if result.provider:
                self._log_failed_auth(request, result)
                raise AuthenticationFailed(_(result.error or 'Token validation failed.'))
            return None
        
        # Map the token to a user or external application
        if result.is_user_token:
            return self._authenticate_user(request, result)
        else:
            return self._authenticate_application(request, result)
    
    def _authenticate_user(
        self, 
        request, 
        result: TokenValidationResult
    ) -> Tuple[User, dict]:
        """
        Authenticate a user token by mapping claims to an existing AAP user.
        """
        provider = result.provider
        claims = result.claims
        
        # Get the user identifier from claims
        user_identifier = claims.get(provider.user_claim)
        
        if not user_identifier:
            logger.warning(
                f"Token from {provider.name} missing user claim '{provider.user_claim}'"
            )
            raise AuthenticationFailed(_('Token missing user identifier.'))
        
        # Find the user in AAP
        user = self._find_user(user_identifier, provider)
        
        if not user:
            logger.warning(
                f"No AAP user found for '{user_identifier}' from provider {provider.name}"
            )
            raise AuthenticationFailed(_('User not found.'))
        
        if not user.is_active:
            logger.warning(f"User '{user.username}' is not active")
            raise AuthenticationFailed(_('User account is disabled.'))
        
        # Log successful authentication
        self._log_successful_auth(request, user, result)
        
        # Return user and token info
        token_info = {
            'type': 'external_oauth_user',
            'provider': provider.name,
            'claims': claims,
        }
        
        return (user, token_info)
    
    def _authenticate_application(
        self, 
        request, 
        result: TokenValidationResult
    ) -> Tuple[ExternalOAuthUser, dict]:
        """
        Authenticate a service principal token by mapping to an external application.
        """
        provider = result.provider
        claims = result.claims
        
        # Get the client ID from claims
        client_id = (
            claims.get(provider.client_id_claim) or 
            claims.get('client_id') or 
            claims.get('azp')
        )
        
        if not client_id:
            logger.warning(
                f"Token from {provider.name} missing client ID claim"
            )
            raise AuthenticationFailed(_('Token missing application identifier.'))
        
        # Find the external application
        try:
            application = ExternalApplication.objects.get(
                provider=provider,
                client_id=client_id,
                enabled=True
            )
        except ExternalApplication.DoesNotExist:
            logger.warning(
                f"No external application found for client_id '{client_id}' "
                f"from provider {provider.name}"
            )
            raise AuthenticationFailed(_('Application not registered.'))
        
        # Update last used timestamp
        application.update_last_used()
        
        # Create pseudo-user for the application
        app_user = ExternalOAuthUser(application, claims)
        
        # Log successful authentication
        self._log_successful_app_auth(request, application, result)
        
        # Return app user and token info
        token_info = {
            'type': 'external_oauth_application',
            'provider': provider.name,
            'application': application.name,
            'client_id': client_id,
            'claims': claims,
        }
        
        return (app_user, token_info)
    
    def _find_user(
        self, 
        identifier: str, 
        provider: ExternalOAuthProvider
    ) -> Optional[User]:
        """
        Find an AAP user by the given identifier.
        
        The identifier is matched against different user fields based on
        the provider's user_claim setting.
        """
        # Map claim types to user fields
        field_mapping = {
            'email': 'email',
            'sub': 'username',  # May need adjustment based on your user model
            'preferred_username': 'username',
            'upn': 'email',  # Azure AD User Principal Name
        }
        
        # Determine which field to search
        search_field = field_mapping.get(provider.user_claim, 'username')
        
        try:
            return User.objects.get(**{search_field: identifier})
        except User.DoesNotExist:
            # Try alternate fields
            for field in ['email', 'username']:
                if field != search_field:
                    try:
                        return User.objects.get(**{field: identifier})
                    except User.DoesNotExist:
                        continue
            return None
        except User.MultipleObjectsReturned:
            logger.error(
                f"Multiple users found for identifier '{identifier}' "
                f"(field: {search_field})"
            )
            return None
    
    def _log_successful_auth(
        self, 
        request, 
        user: User, 
        result: TokenValidationResult
    ):
        """Log a successful user authentication event."""
        log_auth_event(
            smart_str(
                f"User {user.username} authenticated via external OAuth "
                f"(provider: {result.provider.name}, method: {request.method}, "
                f"path: {request.path})"
            ),
            logger,
        )
    
    def _log_successful_app_auth(
        self, 
        request, 
        application: ExternalApplication, 
        result: TokenValidationResult
    ):
        """Log a successful application authentication event."""
        log_auth_event(
            smart_str(
                f"External application '{application.name}' authenticated via OAuth "
                f"(provider: {result.provider.name}, client_id: {application.client_id}, "
                f"method: {request.method}, path: {request.path})"
            ),
            logger,
        )
    
    def _log_failed_auth(self, request, result: TokenValidationResult):
        """Log a failed authentication event."""
        log_auth_event(
            smart_str(
                f"External OAuth authentication failed "
                f"(provider: {result.provider.name if result.provider else 'unknown'}, "
                f"error: {result.error}, method: {request.method}, path: {request.path})"
            ),
            logger,
        )
    
    def authenticate_header(self, request):
        """Return the WWW-Authenticate header value for 401 responses."""
        return f'{self.keyword} realm="api"'
