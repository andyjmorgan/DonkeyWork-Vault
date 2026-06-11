# Self-Hosting

DonkeyWork Vault runs as one HTTP service plus Postgres. The service includes the REST API, OAuth flows, and React web app.

The container listens on port `8080` and exposes health at:

```text
/healthz
```

## Requirements

- A Postgres database.
- A public HTTPS URL for the vault.
- An OIDC identity provider for web app and CLI login, such as Keycloak, Entra ID, Auth0, Okta, Cognito, Authentik, or Zitadel.
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

.NET configuration can be supplied with environment variables by replacing `:` with `__`.

| Setting | Environment variable | Meaning |
|---|---|---|
| `Vault:Persistence:ConnectionString` | `Vault__Persistence__ConnectionString` | Postgres connection string. |
| `Vault:Crypto:ActiveKekId` | `Vault__Crypto__ActiveKekId` | KEK id used for new secrets. |
| `Vault:Crypto:Keks:<id>` | `Vault__Crypto__Keks__<id>` | Base64 32-byte key material. |
| `Vault:PublicBaseUrl` | `Vault__PublicBaseUrl` | Public vault origin, used for OAuth callback URLs. |
| `Vault:RunMigrationsOnStartup` | `Vault__RunMigrationsOnStartup` | Defaults to `true`. |
| `Oidc:Authority` | `Oidc__Authority` | Public OIDC issuer URL. |
| `Oidc:InternalAuthority` | `Oidc__InternalAuthority` | Optional in-cluster metadata/JWKS URL. |
| `Oidc:WebClientId` | `Oidc__WebClientId` | Web app login client id. The legacy `Oidc:ClientId` still works and falls back to `Oidc:Audience`. |
| `Oidc:CliClientId` | `Oidc__CliClientId` | CLI OAuth device-login client id. Defaults to `donkeywork-vault-cli`. |
| `Oidc:Audience` | `Oidc__Audience` | Optional expected audience/client fallback. |
| `Oidc:WebScopes` | `Oidc__WebScopes` | Web app login scopes. The legacy `Oidc:Scopes` still works. Defaults to `openid profile email`. |
| `Oidc:CliScopes` | `Oidc__CliScopes` | CLI device-login scopes. Defaults to `openid profile email offline_access`. |
| `Oidc:RequireHttpsMetadata` | `Oidc__RequireHttpsMetadata` | Defaults to `true`. |

The deprecated `Keycloak:*` section is still honored as a fallback, but new deployments should use `Oidc:*`.

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
      Vault__Persistence__ConnectionString: Host=postgres;Port=5432;Database=vault;Username=vault;Password=change-me
      Vault__Crypto__ActiveKekId: local_2026_06
      Vault__Crypto__Keks__local_2026_06: replace-with-openssl-rand-base64-32-output
      Vault__PublicBaseUrl: https://vault.example.com
      Oidc__Authority: https://idp.example.com/realms/vault
      Oidc__WebClientId: donkeywork-vault
      Oidc__CliClientId: donkeywork-vault-cli
      Oidc__WebScopes: openid profile email

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

The web app uses Authorization Code with PKCE and requests `Oidc:WebScopes`.

## CLI Device-Login Client

The `dwvault` CLI signs in with the OAuth 2.0 Device Authorization Grant (with PKCE S256). Create a second public client in your IdP for it:

1. Create a public client whose id matches `Oidc:CliClientId` (default `donkeywork-vault-cli`).
2. Enable the Device Authorization Grant on the client.
3. Allow and request the `offline_access` scope so refresh tokens survive long-running CLI use.
4. Make sure CLI access tokens carry the vault's audience. In Keycloak, add an audience mapper or client scope for the vault client.

No redirect URI is needed; the device flow does not use one. The vault advertises the client id and scopes to the CLI at login time, so no CLI-side configuration is required.

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

By default, the vault runs EF Core migrations on startup:

```text
Vault:RunMigrationsOnStartup=true
```

Set it to `false` only if you run migrations separately as part of your deployment process.

## KEK Rotation

To rotate encryption keys:

1. Generate a new base64 32-byte KEK.
2. Add it under a new id in `Vault:Crypto:Keks`.
3. Set `Vault:Crypto:ActiveKekId` to the new id.
4. Keep all previous KEKs configured so existing rows can still be decrypted.

New secrets use the active KEK. Existing ciphertext embeds the KEK id that was used when it was written.
