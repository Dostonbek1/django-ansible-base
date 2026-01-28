# External OAuth Token Authentication POC

**ANSTRAT-1611: API Authorization through External OAuth Token**

This module provides authentication for AAP API requests using OAuth tokens
issued by external identity providers (e.g., Azure AD/Entra ID, Ping Federate,
generic OIDC providers).

## Overview

This POC implements the core functionality described in the SDP:

1. **External OAuth Provider Configuration** (P1) - Models and API for configuring
   external identity providers with their JWKS/introspection endpoints.

2. **Token Validation** (P2) - JWT validation using JWKS and opaque token validation
   via introspection endpoints.

3. **External Application Management** (P3) - Models and API for registering external
   applications with RBAC permissions.

4. **Token-to-User/Application Mapping** (P4) - Mapping external token claims to
   AAP users or registered external applications.

## Installation

1. Add `'ansible_base.external_oauth'` to `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    # ...
    'ansible_base.external_oauth',
]
```

2. Run migrations:

```bash
python manage.py migrate
```

3. Add the authentication class to DRF settings:

```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'ansible_base.external_oauth.authentication.ExternalOAuthAuthentication',
        # Keep existing authenticators for backward compatibility
        'ansible_base.oauth2_provider.authentication.LoggedOAuth2Authentication',
        'aap_gateway_api.authentication.basic_auth.LoggedBasicAuthentication',
    ],
}
```

4. Include the URLs in your URL configuration:

```python
urlpatterns = [
    # ...
    path('api/gateway/v1/', include('ansible_base.external_oauth.urls')),
]
```

## API Endpoints

### Identity Providers

- `GET /api/gateway/v1/identity_providers/` - List identity provider configurations
- `POST /api/gateway/v1/identity_providers/` - Create provider configuration
- `GET /api/gateway/v1/identity_providers/{id}/` - Get provider details
- `PUT/PATCH /api/gateway/v1/identity_providers/{id}/` - Update provider
- `DELETE /api/gateway/v1/identity_providers/{id}/` - Delete provider
- `POST /api/gateway/v1/identity_providers/{id}/test_connection/` - Test provider connectivity

### Identity Provider Applications

- `GET /api/gateway/v1/identity_provider_applications/` - List applications
- `POST /api/gateway/v1/identity_provider_applications/` - Create application
- `GET /api/gateway/v1/identity_provider_applications/{id}/` - Get application details
- `PUT/PATCH /api/gateway/v1/identity_provider_applications/{id}/` - Update application
- `DELETE /api/gateway/v1/identity_provider_applications/{id}/` - Delete application

### Identity Provider Role Assignments

- `GET /api/gateway/v1/identity_provider_role_assignments/` - List role assignments
- `POST /api/gateway/v1/identity_provider_role_assignments/` - Create role assignment
- `DELETE /api/gateway/v1/identity_provider_role_assignments/{id}/` - Delete role assignment

## Usage Example

### 1. Configure an Entra ID Provider

```bash
curl -X POST http://localhost:8000/api/gateway/v1/identity_providers/ \
  -H "Authorization: Basic <admin_creds>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Entra ID Production",
    "provider_type": "entra_id",
    "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
    "jwks_uri": "https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys",
    "expected_audience": "<your-app-client-id>",
    "user_claim": "email",
    "client_id_claim": "azp"
  }'
```

### 2. Register an Identity Provider Application (for service principals)

```bash
curl -X POST http://localhost:8000/api/gateway/v1/identity_provider_applications/ \
  -H "Authorization: Basic <admin_creds>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CI/CD Pipeline",
    "provider": 1,
    "client_id": "<service-principal-client-id>",
    "description": "Automated deployment pipeline"
  }'
```

### 3. Assign Roles to the Identity Provider Application

```bash
curl -X POST http://localhost:8000/api/gateway/v1/identity_provider_role_assignments/ \
  -H "Authorization: Basic <admin_creds>" \
  -H "Content-Type: application/json" \
  -d '{
    "application": 1,
    "role_definition": "Job Template Admin"
  }'
```

### 4. Authenticate Using External Token

```bash
# Get a token from Entra ID (using Azure CLI or your preferred method)
TOKEN=$(az account get-access-token --resource <your-app-client-id> --query accessToken -o tsv)

# Use it to call AAP API
curl http://localhost:8000/api/gateway/v1/job_templates/ \
  -H "Authorization: Bearer $TOKEN"
```

## Token Flow

1. Client obtains OAuth token from external provider (Entra ID, etc.)
2. Client sends API request with `Authorization: Bearer <token>`
3. `ExternalOAuthAuthentication` extracts the token
4. Token validator identifies the issuer and finds matching provider
5. Token is validated (JWT signature or introspection)
6. Claims are extracted and mapped to AAP user or external application
7. Request proceeds with appropriate permissions

## Supported Providers

- **Azure AD / Entra ID**: Full support with JWT validation via JWKS
- **Generic OIDC**: Any OIDC-compliant provider with JWKS endpoint
- **Custom OAuth 2.0**: Providers with token introspection endpoint

## Security Considerations

- Client secrets are stored encrypted
- Token validation includes signature, expiration, audience, and issuer checks
- Failed authentication attempts are logged for audit
- JWKS keys are cached to prevent excessive external calls
- Provider unavailability triggers graceful degradation (other auth methods still work)

## Limitations (POC)

This is a proof-of-concept implementation. Production implementation should:

1. Integrate with full RBAC system in django-ansible-base
2. Add comprehensive test coverage
3. Implement admin UI (per P5 in SDP)
4. Add feature flag controls
5. Implement rate limiting for auth failures
6. Add more detailed audit logging

## Files

```
ansible_base/external_oauth/
├── __init__.py
├── apps.py
├── authentication.py       # DRF authentication class
├── models/
│   ├── __init__.py
│   ├── external_oauth_provider.py
│   └── external_application.py
├── serializers/
│   ├── __init__.py
│   ├── provider.py
│   └── application.py
├── token_validator.py      # JWT/introspection validation
├── urls.py
├── views/
│   ├── __init__.py
│   ├── provider.py
│   └── application.py
└── README.md
```
