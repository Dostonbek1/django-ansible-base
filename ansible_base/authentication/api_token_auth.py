"""
External OAuth Token Authentication for Django REST Framework

This module provides a DRF authentication class that validates OAuth tokens
from external identity providers using the external_oauth_consumer authenticator plugins.

See SDP ANSTRAT-1611 for design details.
"""

import logging
from typing import Optional, Tuple

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

logger = logging.getLogger('ansible_base.authentication.api_token_auth')


class ExternalOAuthTokenAuthentication(BaseAuthentication):
    """
    DRF authentication class that validates external OAuth tokens
    using configured authenticator plugins with category='api_auth'.

    Usage:
        Add to REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES']:

        REST_FRAMEWORK = {
            'DEFAULT_AUTHENTICATION_CLASSES': [
                'ansible_base.authentication.api_token_auth.ExternalOAuthTokenAuthentication',
                # ... other authentication classes
            ]
        }
    """

    keyword = 'Bearer'

    def authenticate(self, request: Request) -> Optional[Tuple]:
        """
        Authenticate the request using external OAuth tokens.

        Returns:
            (user, auth_info) tuple if authentication succeeds
            None if this authenticator doesn't apply (no Bearer token)

        Raises:
            AuthenticationFailed: If token is present but invalid
        """
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')

        if not auth_header:
            return None

        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != self.keyword.lower():
            return None

        token = parts[1]

        # Import here to avoid circular imports
        from ansible_base.authentication.models import Authenticator
        from ansible_base.authentication.authenticator_plugins.utils import get_authenticator_plugin

        # Query all enabled external OAuth authenticators in priority order
        authenticators = Authenticator.objects.filter(
            enabled=True,
            category='api_auth',
            type='external_oauth_consumer',
        ).order_by('order')

        if not authenticators.exists():
            # No external OAuth authenticators configured, let other auth methods try
            return None

        for auth in authenticators:
            try:
                plugin_class = get_authenticator_plugin(auth.type)
                plugin = plugin_class(database_instance=auth)
                plugin.set_logger(logger)

                # Validate the token
                claims = plugin.validate_token(token)
                if claims is None:
                    continue  # Token not valid for this provider, try next

                # Map claims to user
                user = plugin.resolve_identity(claims)
                if user:
                    logger.info(f"External OAuth authentication successful via {auth.name}")
                    return (user, {
                        'type': 'external_oauth',
                        'claims': claims,
                        'authenticator_id': auth.id,
                        'authenticator_name': auth.name,
                    })
                else:
                    # Token valid but no matching user - continue to next authenticator
                    # in case another authenticator has this user linked
                    continue

            except Exception as e:
                logger.warning(f"Error during external OAuth authentication with {auth.name}: {e}")
                continue

        # Token was present but couldn't be validated/mapped by any authenticator
        # Don't raise AuthenticationFailed here - let other auth methods try
        # The token might be a local OAuth2 token or PAT
        return None

    def authenticate_header(self, request: Request) -> str:
        """
        Return the WWW-Authenticate header value for 401 responses.
        """
        return f'{self.keyword} realm="AAP API"'
