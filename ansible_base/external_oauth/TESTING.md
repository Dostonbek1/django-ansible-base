# Testing External OAuth Authentication

This guide walks through testing the External OAuth Authentication feature using a local Keycloak instance as the identity provider.

## Prerequisites

- Docker and docker-compose installed
- AAP Gateway development environment set up
- Access to the `aap-gateway` repository

## Step 1: Enable Keycloak in Docker Compose

Edit `container-startup.yml` and uncomment the Keycloak line:

```yaml
keycloak_enabled: True
```

Then restart the development environment:

```bash
make docker-compose
```

Wait for all containers to start (check with `docker ps`).

## Step 2: Verify Keycloak is Running

```bash
# Check Keycloak OIDC configuration
curl -k -s https://localhost:8443/auth/realms/gateway/.well-known/openid-configuration | python3 -m json.tool
```

Expected output should include:
- `issuer`: `https://localhost:8443/auth/realms/gateway`
- `jwks_uri`: `https://localhost:8443/auth/realms/gateway/protocol/openid-connect/certs`
- `token_endpoint`: `https://localhost:8443/auth/realms/gateway/protocol/openid-connect/token`

## Step 3: Get an Access Token from Keycloak

The Keycloak realm has pre-configured test users (see [Pre-configured Test Users](#pre-configured-test-users) below).

```bash
# Get an access token using password grant
TOKEN_RESPONSE=$(curl -k -s -X POST "https://localhost:8443/auth/realms/gateway/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=gateway_oidc_client" \
  -d "client_secret=7b1c3527-8702-4742-af69-2b74ee5742e8" \
  -d "username=gateway_admin" \
  -d "password=admin123")

echo "$TOKEN_RESPONSE" | python3 -m json.tool

# Extract the access token for later use
export KEYCLOAK_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo "Token stored in KEYCLOAK_TOKEN"
```

### Optional: Decode the JWT to inspect claims

```bash
# Decode JWT payload (middle part)
echo "$KEYCLOAK_TOKEN" | cut -d. -f2 | awk '{
    l = length($0);
    pad = l % 4;
    if (pad == 2) $0 = $0 "==";
    else if (pad == 3) $0 = $0 "=";
    print $0;
}' | base64 -d 2>/dev/null | python3 -m json.tool
```

Key claims to look for:
- `iss` - Issuer (matches identity provider configuration)
- `aud` - Audience (must include expected audience)
- `preferred_username` - Used for user mapping
- `is_superuser` - Custom claim for admin status

## Step 4: Register Identity Provider in Gateway

First, get the Keycloak container's IP address on the Docker network:

```bash
KEYCLOAK_IP=$(docker inspect aap_gw_keycloak_1 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' | head -1)
echo "Keycloak IP: $KEYCLOAK_IP"
```

Create the identity provider:

```bash
curl -k -s -X POST "https://localhost/api/gateway/v1/identity_providers/" \
  -H "Content-Type: application/json" \
  -u admin:admin \
  -d "{
    \"name\": \"Local Keycloak\",
    \"provider_type\": \"oidc\",
    \"enabled\": true,
    \"issuer\": \"https://localhost:8443/auth/realms/gateway\",
    \"jwks_uri\": \"https://${KEYCLOAK_IP}:8443/auth/realms/gateway/protocol/openid-connect/certs\",
    \"expected_audience\": \"gateway_oidc_client\",
    \"user_claim\": \"preferred_username\",
    \"jwt_algorithms\": [\"RS256\"],
    \"verify_ssl\": false
  }" | python3 -m json.tool
```

**Important Notes:**
- The `issuer` must match the `iss` claim in tokens (uses `localhost` because that's what Keycloak puts in the token)
- The `jwks_uri` uses the Docker internal IP because Gateway needs to reach Keycloak from inside the container
- `verify_ssl: false` is needed for self-signed certificates in development

## Step 5: Create Matching User in Gateway

The external token's `preferred_username` claim must map to an existing AAP user:

```bash
curl -k -s -X POST "https://localhost/api/gateway/v1/users/" \
  -H "Content-Type: application/json" \
  -u admin:admin \
  -d '{
    "username": "gateway_admin",
    "email": "no.one@nowhere.com",
    "password": "doesntmatter123",
    "first_name": "Gateway",
    "last_name": "Admin"
  }' | python3 -m json.tool
```

## Step 6: Test Authentication with External Token

```bash
# Make sure you have a fresh token (they expire in 5 minutes)
export KEYCLOAK_TOKEN=$(curl -k -s -X POST "https://localhost:8443/auth/realms/gateway/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=gateway_oidc_client" \
  -d "client_secret=7b1c3527-8702-4742-af69-2b74ee5742e8" \
  -d "username=gateway_admin" \
  -d "password=admin123" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Access the /me/ endpoint with the external token
curl -k -s "https://localhost/api/gateway/v1/me/" \
  -H "Authorization: Bearer $KEYCLOAK_TOKEN" | python3 -m json.tool
```

Expected: Should return information about the `gateway_admin` user.

## Step 7: Test Additional Endpoints

```bash
# List organizations
curl -k -s "https://localhost/api/gateway/v1/organizations/" \
  -H "Authorization: Bearer $KEYCLOAK_TOKEN" | python3 -m json.tool

# List services  
curl -k -s "https://localhost/api/gateway/v1/services/" \
  -H "Authorization: Bearer $KEYCLOAK_TOKEN" | python3 -m json.tool
```

## Troubleshooting

### "Token validation failed: Fail to fetch data from the url"

The Gateway container can't reach the JWKS endpoint. Check:
1. The `jwks_uri` uses the Docker internal IP, not `localhost`
2. The Keycloak container is on the same Docker network

```bash
# Verify Gateway can reach Keycloak
docker exec aap_gw_1 curl -k -s -o /dev/null -w "%{http_code}" \
  "https://<KEYCLOAK_IP>:8443/auth/realms/gateway/protocol/openid-connect/certs"
```

### "User not found"

The `user_claim` value from the token doesn't match any AAP user. Either:
1. Create a matching user in AAP
2. Change the `user_claim` field to use a different claim (e.g., `email`)

### "Invalid token audience"

The `expected_audience` doesn't match the `aud` claim in the token. Check:
```bash
# Decode the token and check the 'aud' claim
echo "$KEYCLOAK_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('aud'))"
```

### "Invalid token issuer"

The `issuer` field doesn't match the `iss` claim in the token. The issuer is set by Keycloak based on how clients access it.

### SSL Certificate Errors

Set `verify_ssl: false` on the identity provider for development environments with self-signed certificates.

## Keycloak Configuration Reference

| Setting | Value |
|---------|-------|
| Realm | `gateway` |
| OIDC Client ID | `gateway_oidc_client` |
| Client Secret | `7b1c3527-8702-4742-af69-2b74ee5742e8` |
| Admin Username | `admin` |
| Admin Password | `admin` |
| Token Endpoint | `https://localhost:8443/auth/realms/gateway/protocol/openid-connect/token` |
| JWKS Endpoint | `https://localhost:8443/auth/realms/gateway/protocol/openid-connect/certs` |

### Pre-configured Test Users

| Username | Password | Email | Attributes |
|----------|----------|-------|------------|
| `gateway_admin` | `admin123` | `no.one@nowhere.com` | `is_superuser: true`, Group: `admins` |
| `gateway_unpriv` | `unpriv123` | `noone@nowhere.com` | Normal user |
| `gateway_auditor` | `audit123` | `know.one@nowhere.com` | `is_system_auditor: true`, Group: `auditors` |

## API Endpoints Reference

| Endpoint | Description |
|----------|-------------|
| `GET/POST /api/gateway/v1/identity_providers/` | Manage external OAuth providers |
| `GET/PATCH/DELETE /api/gateway/v1/identity_providers/{id}/` | Single provider operations |
| `POST /api/gateway/v1/identity_providers/{id}/test_connection/` | Test provider connectivity |
| `GET/POST /api/gateway/v1/identity_provider_applications/` | Manage external applications |
| `GET/POST /api/gateway/v1/identity_provider_role_assignments/` | Manage RBAC for external apps |
