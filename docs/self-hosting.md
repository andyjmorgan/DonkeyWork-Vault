# Self-Hosting

DonkeyWork Vault runs as one HTTP service plus Postgres. The service includes the REST API, OAuth flows, and React web app.

The container listens on port `8080` and exposes health at:

```text
/healthz
```

## Requirements

- A Postgres database.
- A public HTTPS URL for the vault.
- An OIDC identity provider for web app login, such as Keycloak, Entra ID, Auth0, Okta, Cognito, Authentik, or Zitadel.
- A 32-byte key-encryption key for vault encryption.

## Build the Container

From the repository root:

```bash
docker build -f Dockerfile.vault -t donkeywork-vault:local .
```

## Generate a KEK

Generate base64-encoded 32-byte key material:

```bash
openssl rand -base64 32
```

Keep this value secret and backed up. If it is lost, encrypted secrets already stored in the database cannot be decrypted.

## Configuration

The service is configured entirely with environment variables.

| Environment variable | Meaning |
|---|---|
| `VAULT_DSN` (or `DATABASE_URL`) | Postgres DSN, e.g. `postgres://vault:pass@postgres:5432/vault`. |
| `VAULT_CRYPTO_ACTIVE_KEK_ID` | KEK id used for new secrets. |
| `VAULT_CRYPTO_KEKS` | `id=base64[,id2=base64…]` — base64 32-byte key material per KEK id. |
| `VAULT_PUBLIC_BASE_URL` | Public vault origin, used for OAuth callback URLs. |
| `VAULT_RUN_MIGRATIONS` | Defaults to `true`. |
| `VAULT_OIDC_AUTHORITY` | Public OIDC issuer URL. Leave blank to disable auth (local/dev only). |
| `VAULT_OIDC_INTERNAL_AUTHORITY` | Optional in-cluster metadata/JWKS URL. |
| `VAULT_OIDC_AUDIENCE` | Expected JWT audience. |
| `VAULT_OIDC_WEB_CLIENT_ID` | SPA login client id. |
| `VAULT_OIDC_CLI_CLIENT_ID` | CLI device-flow client id (default `donkeywork-vault-cli`). |
| `VAULT_OIDC_WEB_SCOPES` | SPA login scopes. Defaults to `openid profile email`. |
| `VAULT_OIDC_CLI_SCOPES` | CLI scopes. Defaults to `openid profile email offline_access`. |
| `VAULT_OIDC_REQUIRE_HTTPS` | Defaults to `true`. |

Full reference: `src/server/internal/config/config.go`.

## Example Docker Compose

```yaml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: vault
      POSTGRES_USER: vault
      POSTGRES_PASSWORD: change-me
    volumes:
      - postgres-data:/var/lib/postgresql/data

  vault:
    image: donkeywork-vault:local
    depends_on:
      - postgres
    ports:
      - "8080:8080"
    environment:
      VAULT_DSN: postgres://vault:change-me@postgres:5432/vault?sslmode=disable
      VAULT_CRYPTO_ACTIVE_KEK_ID: local_2026_06
      VAULT_CRYPTO_KEKS: local_2026_06=replace-with-openssl-rand-base64-32-output
      VAULT_PUBLIC_BASE_URL: https://vault.example.com
      VAULT_OIDC_AUTHORITY: https://idp.example.com/realms/vault
      VAULT_OIDC_AUDIENCE: donkeywork-vault
      VAULT_OIDC_WEB_CLIENT_ID: donkeywork-vault
      VAULT_OIDC_WEB_SCOPES: openid profile email

volumes:
  postgres-data:
```

Put a reverse proxy or ingress in front of the container and terminate HTTPS at `https://vault.example.com`.

## OIDC Login Provider

Create a public/browser OIDC client for the vault web app.

Register these redirect URLs:

```text
https://vault.example.com/
```

Register this post-logout redirect URL if your IdP requires one:

```text
https://vault.example.com/
```

The web app uses Authorization Code with PKCE and requests `Oidc:Scopes`.

## OAuth App Callback URLs

For each third-party OAuth provider you add inside the vault, register this callback URL in that provider's developer portal:

```text
https://vault.example.com/api/oauth/callback
```

This is separate from the OIDC login redirect for the vault web app.

## Start and Verify

Start the stack, then check health:

```bash
curl -f http://localhost:8080/healthz
```

After your reverse proxy is configured:

```bash
curl -f https://vault.example.com/healthz
```

Open the public URL in a browser and sign in through your OIDC provider.

## Point the CLI at Your Vault

```bash
dwvault --addr https://vault.example.com auth login
dwvault --addr https://vault.example.com credentials list
```

Or set:

```bash
export VAULT_ADDR=https://vault.example.com
```

## Migrations

By default, the vault runs its embedded, idempotent SQL migrations on startup:

```text
VAULT_RUN_MIGRATIONS=true
```

Set it to `false` only if you run migrations separately as part of your deployment process.

## KEK Rotation

To rotate encryption keys:

1. Generate a new base64 32-byte KEK.
2. Add it under a new id in `VAULT_CRYPTO_KEKS` (comma-separated `id=base64` pairs).
3. Set `VAULT_CRYPTO_ACTIVE_KEK_ID` to the new id.
4. Keep all previous KEKs configured so existing rows can still be decrypted.

New secrets use the active KEK. Existing ciphertext embeds the KEK id that was used when it was written.
