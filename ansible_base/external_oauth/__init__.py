# External OAuth Token Authentication POC
# ANSTRAT-1611: API Authorization through External OAuth Token
#
# This module provides authentication for API requests using OAuth tokens
# issued by external identity providers (e.g., Entra ID, Ping Federate, OIDC).

default_app_config = 'ansible_base.external_oauth.apps.ExternalOAuthConfig'
