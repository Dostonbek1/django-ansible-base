# External OAuth Consumer Authenticator

**ANSTRAT-1611: API Authorization through External OAuth Token**

This document describes the External OAuth Consumer authenticator plugin, which enables
API authentication using OAuth tokens issued by external identity providers.

## Overview

The External OAuth Consumer is an **authenticator plugin** (`type: external_oauth_consumer`)
that validates Bearer tokens from external identity providers (IdPs) like:

- Azure AD / Entra ID
- Keycloak
- Ping Federate
- Any OIDC-compliant provider

Unlike browser-based SSO authenticators (OIDC, SAML), this plugin handles **API token validation**
for programmatic access—validating tokens that clients obtain directly from IdPs.

## Key Concepts

### Authenticator Plugin Architecture

External OAuth uses the existing **Authenticator plugin framework**:

```
┌─────────────────────────────────────────────────────────────┐
│                    Authenticator Model                      │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ type: "external_oauth_consumer"                     │    │
│  │ category: "api_auth"                                │    │
│  │ configuration: {                                    │    │
│  │   ISSUER_URL, JWKS_URI, USERNAME_CLAIM, ...         │    │
│  │ }                                                   │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ loads
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              AuthenticatorPlugin Class                      │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ validate_token(token) → claims                      │    │
│  │ resolve_identity(claims) → User                     │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Identity Resolution

Tokens can represent two types of identities:

1. **User Tokens**: Mapped to existing AAP users via configurable claims
2. **Service Principal Tokens**: Mapped to managed Users with independent RBAC

```
┌─────────────────────────────────────────────────────────────┐
│                    Token Claims                             │
│  { "sub": "...", "email": "user@example.com", "azp": "..." }│
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Identity Resolution                      │
│  1. Try service principal: AuthenticatorUser(uid=azp,       │
│                            user.managed=True)               │
│  2. Try user: AuthenticatorUser(uid=email/sub,              │
│               user.managed=False)                           │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

### Create an External OAuth Authenticator

```bash
curl -X POST https://gateway/api/gateway/v1/authenticators/ \
  -H "Authorization: Basic <admin_creds>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Entra ID Production",
    "enabled": true,
    "type": "ansible_base.authentication.authenticator_plugins.external_oauth_consumer",
    "configuration": {
      "ISSUER_URL": "https://login.microsoftonline.com/<tenant-id>/v2.0",
      "JWKS_URI": "https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys",
      "EXPECTED_AUDIENCES": ["api://<your-app-id>"],
      "USERNAME_CLAIM": "email",
      "CLIENT_ID_CLAIM": "azp",
      "ALLOWED_ALGORITHMS": ["RS256"],
      "VERIFY_SSL": true
    }
  }'
```

### Configuration Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `ISSUER_URL` | Yes | - | The `iss` claim value expected in tokens |
| `JWKS_URI` | No* | - | URL to fetch public keys for JWT validation |
| `INTROSPECTION_URL` | No* | - | URL for opaque token introspection |
| `CLIENT_ID` | No | - | Client ID for introspection auth |
| `CLIENT_SECRET` | No | - | Client secret for introspection auth (encrypted) |
| `EXPECTED_AUDIENCES` | No | [] | List of valid `aud` claim values |
| `ALLOWED_ALGORITHMS` | No | ["RS256"] | Allowed JWT signing algorithms |
| `USERNAME_CLAIM` | No | "email" | Claim for user identity mapping |
| `CLIENT_ID_CLAIM` | No | "azp" | Claim for service principal mapping |
| `JWKS_CACHE_TIMEOUT` | No | 3600 | JWKS cache TTL in seconds |
| `VERIFY_SSL` | No | true | Verify TLS certificates |

*Either `JWKS_URI` (for JWTs) or `INTROSPECTION_URL` (for opaque tokens) is required.

## User Linking

Users must be linked to the authenticator via `AuthenticatorUser` before they can authenticate:

### Link an Existing User

```bash
curl -X POST https://gateway/api/gateway/v1/authenticator_users/ \
  -H "Authorization: Basic <admin_creds>" \
  -H "Content-Type: application/json" \
  -d '{
    "user": <user_id>,
    "provider": <authenticator_id>,
    "uid": "user@example.com"
  }'
```

The `uid` should match the value in the token's `USERNAME_CLAIM` (e.g., email).

### Auto-Linking via SSO

If users also log in via browser SSO using the same IdP, the `AuthenticatorUser` link
is created automatically during login. These users can then use external tokens for
API access without manual linking.

## Service Principals

Service principals (non-human identities) are represented as **managed Users**:

### Create a Service Principal

```bash
# 1. Create the managed user
curl -X POST https://gateway/api/gateway/v1/users/ \
  -H "Authorization: Basic <admin_creds>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "_sp_cicd-pipeline",
    "first_name": "CI/CD Pipeline",
    "managed": true
  }'

# 2. Link to the authenticator
curl -X POST https://gateway/api/gateway/v1/authenticator_users/ \
  -H "Authorization: Basic <admin_creds>" \
  -H "Content-Type: application/json" \
  -d '{
    "user": <user_id>,
    "provider": <authenticator_id>,
    "uid": "<service-principal-client-id>"
  }'

# 3. Assign RBAC roles
curl -X POST https://gateway/api/gateway/v1/role_user_assignments/ \
  -H "Authorization: Basic <admin_creds>" \
  -H "Content-Type: application/json" \
  -d '{
    "user": <user_id>,
    "role_definition": <role_id>
  }'
```

The `uid` should match the value in the token's `CLIENT_ID_CLAIM` (typically `azp` or `client_id`).

## Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              API Client                                 │
│                    (CI/CD pipeline, external service)                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ 1. Get token from IdP
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     External Identity Provider                          │
│              (Keycloak, Entra ID, Okta, Ping Federate)                  │
└─────────────────────────────────────────────────────────────────────────┘
        │                                        ▲
        │ 2. JWT Token                           │ 4. Fetch JWKS (cached)
        ▼                                        │
┌─────────────────────────────────────────────────────────────────────────┐
│                          AAP Gateway                                    │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  3. ExternalOAuthTokenAuthentication (DRF Auth Class)             │  │
│  │     └─► Query enabled authenticators (category='api_auth')        │  │
│  │         └─► For each: plugin.validate_token() → plugin.resolve()  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  5. Identity Resolution via AuthenticatorUser                     │  │
│  │     ├─► Service Principal: uid=client_id, user.managed=True       │  │
│  │     └─► User: uid=email/sub, user.managed=False                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  6. RBAC Permission Check (standard Django/DRF permissions)       │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Token Validation

### JWT Tokens

For JWT tokens (identified by 3 dot-separated parts):

1. Extract `kid` (Key ID) from JWT header
2. Fetch JWKS from configured `JWKS_URI` (cached)
3. Find matching public key
4. Verify signature using the key
5. Validate claims: `iss`, `aud`, `exp`, `iat`

### Opaque Tokens

For opaque tokens (when `INTROSPECTION_URL` is configured):

1. POST token to introspection endpoint
2. Authenticate using `CLIENT_ID` / `CLIENT_SECRET`
3. Check `active: true` in response
4. Validate `iss` claim if configured

## Error Handling

| Scenario | HTTP Status | Message |
|----------|-------------|---------|
| No Bearer token | - | Returns `None` (other auth methods tried) |
| Invalid signature | 401 | "Authentication failed." |
| Expired token | 401 | "Authentication failed." |
| Invalid audience | 401 | "Authentication failed." |
| No matching user | 401 | "Authentication failed." |
| User inactive | 401 | "Authentication failed." |

Error messages are intentionally generic to prevent information leakage.

## Files

| File | Purpose |
|------|---------|
| `authenticator_plugins/external_oauth_consumer.py` | Plugin class and configuration |
| `api_token_auth.py` | DRF authentication class |

## Related Documentation

- [SDP ANSTRAT-1611](https://handbook.example.com/sdp/ANSTRAT-1611) - System Design Plan
- [Authenticator Plugins](./authentication.md) - General authenticator documentation
- [RBAC](./rbac.md) - Role-based access control
