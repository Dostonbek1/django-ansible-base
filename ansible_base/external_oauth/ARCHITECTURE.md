# External OAuth Authentication - Architecture & Flow

This document explains how the External OAuth Authentication feature works, with a flow diagram and pointers to the relevant code.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              API Client                                     │
│                    (CI/CD pipeline, external service)                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ 1. Get token from IdP
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     External Identity Provider                              │
│              (Keycloak, Entra ID, Okta, Ping Federate)                      │
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                      │
│  │ Token       │    │ JWKS        │    │ Introspect  │                      │
│  │ Endpoint    │    │ Endpoint    │    │ Endpoint    │                      │
│  └─────────────┘    └─────────────┘    └─────────────┘                      │
└─────────────────────────────────────────────────────────────────────────────┘
        │                     ▲                    ▲
        │ 2. JWT Token        │ 4. Fetch JWKS      │ (or introspect)
        ▼                     │                    │
┌─────────────────────────────────────────────────────────────────────────────┐
│                          AAP Gateway                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                  Django REST Framework                               │   │
│  │  ┌────────────────────────────────────────────────────────────────┐  │   │
│  │  │  3. ExternalOAuthAuthentication                                │  │   │
│  │  │     └─► ExternalOAuthTokenValidator                            │  │   │
│  │  │           ├─► 4. Validate JWT signature (JWKS)                 │  │   │
│  │  │           ├─► 5. Check issuer, audience, expiry                │  │   │
│  │  │           └─► 6. Extract claims                                │  │   │
│  │  └────────────────────────────────────────────────────────────────┘  │   │
│  │                              │                                       │   │
│  │                              ▼                                       │   │
│  │  ┌────────────────────────────────────────────────────────────────┐  │   │
│  │  │  7. User/Application Mapping                                   │  │   │
│  │  │     ├─► User Token: Map claims to AAP User                     │  │   │
│  │  │     └─► Service Principal: Map to External Application         │  │   │
│  │  └────────────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         Database                                     │   │
│  │  ┌──────────────────────┐  ┌─────────────────────┐                   │   │
│  │  │ ExternalOAuthProvider│  │ ExternalApplication │                   │   │
│  │  │ (issuer, jwks_uri,   │  │ (client_id, roles,  │                   │   │
│  │  │  audience, etc.)     │  │  provider)          │                   │   │
│  │  └──────────────────────┘  └─────────────────────┘                   │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Detailed Authentication Flow

### Step 1: Client Obtains Token from IdP

The API client authenticates with the external IdP (e.g., Keycloak) and receives a JWT token.

```bash
# Example: Client gets token from Keycloak
curl -X POST "https://keycloak:8443/auth/realms/gateway/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=my-service" \
  -d "client_secret=secret"
```

### Step 2: Client Calls Gateway API with Token

```bash
curl "https://gateway/api/gateway/v1/organizations/" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
```

### Step 3: ExternalOAuthAuthentication Intercepts Request

**File:** `authentication.py` → `ExternalOAuthAuthentication.authenticate()`

```python
def authenticate(self, request) -> Optional[Tuple]:
    # Extract the Authorization header
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    
    # Check if it's a Bearer token
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None  # Let other authenticators try
    
    token = parts[1]
    
    # Validate the token
    validator = get_token_validator()
    result = validator.validate_token(token)
```

📁 **Location:** `authentication.py` lines 97-125, class `ExternalOAuthAuthentication`, method `authenticate()`

### Step 4: Token Validator Determines Provider

**File:** `token_validator.py` → `ExternalOAuthTokenValidator.validate_token()`

The validator first extracts the `iss` (issuer) claim from the JWT without verifying the signature:

```python
def _extract_issuer(self, token: str) -> Optional[str]:
    # Decode without verification to get claims
    unverified = jwt.decode(token, options={"verify_signature": False})
    return unverified.get('iss')
```

Then finds a matching provider in the database:

```python
def _find_provider_by_issuer(self, issuer: str) -> Optional[ExternalOAuthProvider]:
    return ExternalOAuthProvider.objects.get(issuer=issuer, enabled=True)
```

📁 **Location:** `token_validator.py` lines 136-152, methods `_extract_issuer()` and `_find_provider_by_issuer()`

### Step 5: JWT Signature Validation

**File:** `token_validator.py` → `_validate_jwt_token()`

The validator fetches JWKS keys from the provider and validates the signature:

```python
def _validate_jwt_token(self, token: str, provider: ExternalOAuthProvider):
    # Get JWK client (caches keys)
    jwk_client = self._get_jwk_client(provider)
    
    # Get the signing key for this token
    signing_key = jwk_client.get_signing_key_from_jwt(token)
    
    # Decode and verify signature, expiry, issuer, audience
    claims = jwt.decode(
        token,
        key=signing_key.key,
        algorithms=provider.get_jwt_algorithms(),
        audience=provider.get_expected_audiences(),
        issuer=provider.issuer
    )
```

📁 **Location:** `token_validator.py` lines 154-196, method `_validate_jwt_token()`

### Step 6: Determine Token Type (User vs Service Principal)

**File:** `token_validator.py` → `_is_user_token()`

```python
def _is_user_token(self, claims: Dict[str, Any], provider: ExternalOAuthProvider) -> bool:
    # Azure AD / Entra ID specific: check for 'idtyp' claim
    if claims.get('idtyp') == 'app':
        return False
    
    # If sub equals azp/client_id, it's likely a service principal
    sub = claims.get('sub')
    client_id = claims.get(provider.client_id_claim)
    if sub and client_id and sub == client_id:
        return False
    
    # If there's no user-identifying claim, treat as service principal
    user_claim = claims.get(provider.user_claim)
    if not user_claim:
        return False
    
    return True
```

📁 **Location:** `token_validator.py` lines 325-354, method `_is_user_token()`

### Step 7: Map to AAP User or External Application

**File:** `authentication.py` → `_authenticate_user()` or `_authenticate_application()`

#### For User Tokens:

```python
def _authenticate_user(self, request, result: TokenValidationResult):
    provider = result.provider
    claims = result.claims
    
    # Get the user identifier from claims (e.g., email, preferred_username)
    user_identifier = claims.get(provider.user_claim)
    
    # Find the user in AAP
    user = self._find_user(user_identifier, provider)
    
    if not user:
        raise AuthenticationFailed(_('User not found.'))
    
    return (user, {'type': 'external_oauth_user', 'provider': provider.name})
```

📁 **Location:** `authentication.py` lines 150-193, method `_authenticate_user()`

#### For Service Principal Tokens:

```python
def _authenticate_application(self, request, result: TokenValidationResult):
    provider = result.provider
    claims = result.claims
    
    # Get client ID from claims
    client_id = claims.get(provider.client_id_claim)
    
    # Find registered external application
    application = ExternalApplication.objects.get(
        client_id=client_id,
        provider=provider,
        enabled=True
    )
    
    # Return pseudo-user object with application's roles
    return (ExternalOAuthUser(application, claims), {'type': 'external_oauth_app'})
```

📁 **Location:** `authentication.py` lines 195-239, method `_authenticate_application()`

## Data Models

### ExternalOAuthProvider

**File:** `models/external_oauth_provider.py`

Stores configuration for each external identity provider:

| Field | Description |
|-------|-------------|
| `name` | Unique identifier for the provider |
| `provider_type` | `oidc`, `entra_id`, or `oauth2` |
| `issuer` | Expected `iss` claim value (e.g., `https://login.microsoftonline.com/{tenant}/v2.0`) |
| `jwks_uri` | URL to fetch public keys for JWT signature verification |
| `expected_audience` | Expected `aud` claim (comma-separated for multiple) |
| `user_claim` | Claim to map to AAP username (e.g., `email`, `preferred_username`) |
| `client_id_claim` | Claim identifying service principals (e.g., `azp`, `client_id`) |
| `verify_ssl` | Whether to verify SSL when fetching JWKS |

### ExternalApplication

**File:** `models/external_application.py`

Represents a service principal (non-human identity):

| Field | Description |
|-------|-------------|
| `name` | Display name for the application |
| `client_id` | The `azp` or `client_id` claim value from tokens |
| `provider` | Foreign key to `ExternalOAuthProvider` |
| `enabled` | Whether this application can authenticate |

### ExternalApplicationRoleAssignment

**File:** `models/external_application.py`

Assigns RBAC roles to external applications:

| Field | Description |
|-------|-------------|
| `application` | Foreign key to `ExternalApplication` |
| `role_definition` | Reference to DAB role definition |
| `content_type` | Optional: scope role to specific resource type |
| `object_id` | Optional: scope role to specific resource instance |

## Key Design Decisions

### 1. Graceful Degradation

If an external provider is unavailable, the authenticator returns `None` instead of failing, allowing other authentication methods (PAT, session, etc.) to be tried:

```python
except ProviderUnavailableError as e:
    logger.error(f"External OAuth provider unavailable: {e}")
    return None  # Let other authenticators try
```

### 2. Provider Matching by Issuer

The issuer (`iss`) claim uniquely identifies the provider, enabling support for multiple providers simultaneously.

### 3. Dual Token Type Support

The same authentication class handles both:
- **User tokens**: Mapped to existing AAP users
- **Service principal tokens**: Mapped to registered External Applications with specific RBAC roles

### 4. JWKS Caching

Public keys are cached to avoid hitting the IdP on every request:

```python
self._jwk_clients[provider.pk] = PyJWKClient(
    provider.jwks_uri,
    cache_jwk_set=True,
    lifespan=provider.jwks_cache_timeout  # Default: 1 hour
)
```

## File Reference

| File | Purpose |
|------|---------|
| `authentication.py` | DRF authentication class, user/app mapping |
| `token_validator.py` | JWT validation, JWKS fetching, provider matching |
| `models/external_oauth_provider.py` | Provider configuration model |
| `models/external_application.py` | External application & role assignment models |
| `views/provider.py` | API viewset for managing providers |
| `views/application.py` | API viewset for managing applications |
| `serializers/provider.py` | DRF serializer for provider model |
| `serializers/application.py` | DRF serializer for application model |
| `urls.py` | URL routing for API endpoints |
