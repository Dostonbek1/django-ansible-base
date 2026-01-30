# Testing External OAuth Consumer

This guide walks through testing the External OAuth Consumer authenticator plugin with a local Keycloak instance.

## Prerequisites

- Docker Compose environment running (`make docker-compose`)
- Keycloak enabled in `container-startup.yml`:
  ```yaml
  keycloak_enabled: True
  ```

## Step 1: Get Keycloak Container IP

The Gateway container needs to reach Keycloak's JWKS endpoint. Get the internal IP:

```bash
KEYCLOAK_IP=$(docker inspect aap_gw_keycloak_1 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "Keycloak IP: $KEYCLOAK_IP"
```

## Step 2: Create an External OAuth Authenticator

```bash
curl -k -X POST "https://localhost/api/gateway/v1/authenticators/" \
  -u admin:admin \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Keycloak External OAuth\",
    \"enabled\": true,
    \"type\": \"ansible_base.authentication.authenticator_plugins.external_oauth_consumer\",
    \"configuration\": {
      \"ISSUER_URL\": \"https://localhost:8443/auth/realms/gateway\",
      \"JWKS_URI\": \"https://${KEYCLOAK_IP}:8443/auth/realms/gateway/protocol/openid-connect/certs\",
      \"EXPECTED_AUDIENCES\": [],
      \"USERNAME_CLAIM\": \"preferred_username\",
      \"CLIENT_ID_CLAIM\": \"azp\",
      \"VERIFY_SSL\": false
    }
  }"
```

Note the returned `id` value (e.g., `1`).

## Step 3: Get User ID

```bash
curl -k -s "https://localhost/api/gateway/v1/users/?username=admin" \
  -u admin:admin | python3 -m json.tool
```

Note the `id` from the results (e.g., `1`).

## Step 4: Link User to Authenticator

The AuthenticatorUser API is read-only, so create the link via Django shell.

Replace `<AUTH_ID>` and `<USER_ID>` with the values from previous steps:

```bash
docker exec aap_gw_1 /opt/aap_gateway/venv/bin/python -m aap_gateway_api shell -c "
from django.contrib.auth import get_user_model
from ansible_base.authentication.models import Authenticator, AuthenticatorUser
User = get_user_model()
user = User.objects.get(id=<USER_ID>)
auth = Authenticator.objects.get(id=<AUTH_ID>)
obj, created = AuthenticatorUser.objects.get_or_create(user=user, provider=auth, defaults={'uid': 'gateway_admin'})
print(f'Created: {created}, AuthenticatorUser ID: {obj.id}')
"
```

The `uid` must match the `preferred_username` claim in Keycloak tokens (which is `gateway_admin` for the test user).

## Step 5: Get Token from Keycloak

```bash
TOKEN=$(curl -k -s -X POST "https://localhost:8443/auth/realms/gateway/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=gateway_oidc_client" \
  -d "client_secret=7b1c3527-8702-4742-af69-2b74ee5742e8" \
  -d "username=gateway_admin" \
  -d "password=admin123" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token: ${TOKEN:0:50}..."
```

## Step 6: Test Authentication

```bash
curl -k -s "https://localhost/api/gateway/v1/me/" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### Expected Success Response

```json
{
  "results": [
    {
      "id": 1,
      "username": "admin",
      ...
    }
  ]
}
```

### If Authentication Fails

Check Gateway logs:

```bash
docker logs aap_gw_gateway_1 --tail 100 | grep -i oauth
```

Common issues:
- **"No user found for identifier"**: The `uid` in AuthenticatorUser doesn't match the token's `USERNAME_CLAIM`
- **"Token issuer mismatch"**: The `ISSUER_URL` doesn't match the token's `iss` claim
- **"Failed to get signing key"**: JWKS endpoint unreachable (check `KEYCLOAK_IP` and `VERIFY_SSL`)

## Testing Service Principals

To test service principal authentication:

### 1. Create a Managed User

```bash
curl -k -X POST "https://localhost/api/gateway/v1/users/" \
  -u admin:admin \
  -H "Content-Type: application/json" \
  -d '{
    "username": "_sp_test_app",
    "first_name": "Test Application",
    "managed": true
  }'
```

### 2. Link with Client ID

```bash
curl -k -X POST "https://localhost/api/gateway/v1/authenticator_users/" \
  -u admin:admin \
  -H "Content-Type: application/json" \
  -d '{
    "user": <SP_USER_ID>,
    "provider": <AUTH_ID>,
    "uid": "gateway_oidc_client"
  }'
```

The `uid` should match the `azp` (or `CLIENT_ID_CLAIM`) in tokens.

### 3. Get Client Credentials Token

```bash
TOKEN=$(curl -k -s -X POST "https://localhost:8443/auth/realms/gateway/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=gateway_oidc_client" \
  -d "client_secret=7b1c3527-8702-4742-af69-2b74ee5742e8" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

### 4. Test

```bash
curl -k -s "https://localhost/api/gateway/v1/me/" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

## Keycloak Test Users

| Username | Password | Description |
|----------|----------|-------------|
| `gateway_admin` | `admin123` | Test user for user token flow |
| `admin` | `admin` | Keycloak admin console |

## Configuration Reference

| Field | Description |
|-------|-------------|
| `ISSUER_URL` | Expected `iss` claim (use external URL) |
| `JWKS_URI` | JWKS endpoint (use internal IP for container-to-container) |
| `USERNAME_CLAIM` | Claim for user mapping (default: `email`) |
| `CLIENT_ID_CLAIM` | Claim for service principal mapping (default: `azp`) |
| `VERIFY_SSL` | Set `false` for self-signed certs |
