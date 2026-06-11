# API Access

The web app and CLI use the same REST API.

The generated OpenAPI document is available from the running service at:

```text
/openapi/v1.json
```

The repository also includes:

```text
api/openapi.json
```

## Authentication

Use a `dwv_...` access key from **Profile**.

Preferred header:

```bash
curl -H "X-Api-Key: $VAULT_API_KEY" https://vault.example.com/api/v1/me
```

Bearer form is also supported:

```bash
curl -H "Authorization: Bearer $VAULT_API_KEY" https://vault.example.com/api/v1/me
```

## Common Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/me` | Current caller identity. |
| `GET` | `/api/v1/api-keys` | List stored API-key credentials. |
| `POST` | `/api/v1/api-keys` | Create a credential. |
| `GET` | `/api/v1/api-keys/{name}/reveal` | Reveal a credential secret and assembled header. |
| `GET` | `/api/v1/credentials/{name}` | Read credential shape without the secret. |
| `GET` | `/api/v1/oauth/tokens` | List connected OAuth accounts. |
| `GET` | `/api/v1/oauth/{provider}/token` | Retrieve a live OAuth access token. |
| `GET` | `/api/v1/access-keys` | List access keys. |
| `POST` | `/api/v1/access-keys` | Create an access key. Secret is returned once. |
| `GET` | `/api/v1/audit` | Query audit events. Requires `vault:audit`. |

## Examples

List credentials:

```bash
curl -H "X-Api-Key: $VAULT_API_KEY" \
  https://vault.example.com/api/v1/api-keys
```

Reveal a complete header:

```bash
curl -sS -H "X-Api-Key: $VAULT_API_KEY" \
  https://vault.example.com/api/v1/api-keys/grafana-prod/reveal
```

Create a credential:

```bash
curl -sS -X POST \
  -H "X-Api-Key: $VAULT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "grafana-prod",
    "secret": "replace-me",
    "description": "Grafana production API",
    "baseUrl": "https://grafana.example.com",
    "docsUrl": "https://grafana.com/docs/grafana/latest/developers/http_api/",
    "header": "Authorization",
    "prefix": "Bearer ",
    "kind": "header_api_key"
  }' \
  https://vault.example.com/api/v1/api-keys
```

Get an OAuth token:

```bash
curl -sS -H "X-Api-Key: $VAULT_API_KEY" \
  https://vault.example.com/api/v1/oauth/github/token
```

