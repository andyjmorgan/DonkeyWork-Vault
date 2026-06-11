# Security and Operations

## Encryption

Secrets are encrypted before storage using envelope encryption.

Each stored secret gets a data-encryption key. The data key encrypts the secret with AES-256-GCM, and the configured key-encryption key wraps the data key.

The database stores ciphertext and metadata needed to decrypt it later. Plaintext secrets are decrypted only inside the vault process when a caller is authorized to reveal or use them.

## Access Keys

Machine callers use access keys that start with `dwv_`.

Access keys can be sent as either:

```text
X-Api-Key: dwv_...
```

or:

```text
Authorization: Bearer dwv_...
```

The vault stores only a hash and display prefix for each access key. The full secret is shown once at creation time and cannot be recovered later.

## Scopes

Every API request is scope-gated.

| Scope | Grants |
|---|---|
| `vault:read` | Read/list credentials, OAuth tokens, manifests, configs, and identity. |
| `vault:readwrite` | Mutating operations such as create, update, connect, delete, enable, and disable. Implies read. |
| `vault:audit` | Read the audit trail. |

Issue scripts and agents the smallest scope they need. Most runtime use should need only `vault:read`.

## OAuth Security

OAuth connection flows use Authorization Code with PKCE S256.

The vault stores short-lived OAuth state rows during connection. The provider and owner are carried in server-side state, not in the callback URL.

When users select scopes, the vault filters the requested scopes against the provider's declared scope catalog and defaults before building the authorize URL.

Access tokens and refresh tokens are encrypted at rest. When a token is requested, the vault refreshes it when possible and returns a live access token.

## Audit Logging

The vault records security-relevant events such as:

- Credential access.
- OAuth token access.
- OAuth token refresh.
- OAuth token connection.
- Access key authentication success or failure.
- Scope denial.
- Audit trail access.

Audit records include references such as user id, tenant id, access key prefix/name, target provider/account/name, source IP, method, outcome, and detail. They do not include plaintext secrets.

Default audit retention is configured under `Vault:Audit`. The built-in defaults include 180 days of retention.

## Operational Practices

- Use HTTPS for every production deployment.
- Keep Postgres private to the vault service.
- Back up Postgres and all configured KEKs together.
- Store KEKs in your deployment secret manager, not in source control.
- Rotate access keys periodically and after staff, host, or pipeline changes.
- Prefer one access key per script, host, CI job, or agent identity.
- Disable access keys before deleting them when investigating suspicious use.
- Avoid logging command lines that include expanded secrets.
- Avoid verbose HTTP client logging when injecting credentials.

