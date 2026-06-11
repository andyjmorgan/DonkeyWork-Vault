# Web App Guide

The web app is the main console for humans. It is served by the same vault service as the API.

## Navigation

The signed-in app has these areas:

- **Credentials**: store and reveal API keys, passwords, connection strings, SSH credentials, and connected OAuth tokens.
- **Providers**: add OAuth providers, edit scopes and authorize parameters, and save OAuth app client credentials.
- **OAuth Connect**: connect an OAuth account after its provider and app credentials are configured.
- **Audit trail**: review credential access, auth events, token refreshes, and failures.
- **Profile**: view your identity and manage scoped `dwv_...` access keys for the CLI and agents.

## Credentials

Use **Credentials** to store non-OAuth secrets and to reveal connected OAuth access tokens.

When adding a credential, use a stable name. Scripts and agents use this name later:

```bash
dwvault credentials get grafana-prod
```

Credential kinds:

| Kind | Use |
|---|---|
| Opaque | Return the secret as-is. Useful for HMAC secrets, DSNs, and custom formats. |
| Header API key | Send the secret in a configured HTTP header, optionally with a prefix. |
| HTTP Basic | Store a username and password; the vault assembles `Authorization: Basic ...`. |
| Username + password | Store login material that is not HTTP Basic. |
| SSH | Store SSH login metadata and secret material. |
| Connection string | Store a whole DSN or connection string as the secret. |

For header credentials, set:

- **Header**: for example `Authorization` or `X-Api-Key`.
- **Prefix**: for example `Bearer `. Include the trailing space when the service expects one.

Use **Reveal** only when you need to copy a value manually. The CLI is usually safer for scripts because it prints only the requested secret or header.

## Providers

Use **Providers** before using **OAuth Connect**.

The built-in library contains provider templates such as Google, Microsoft, GitHub, Dropbox, and Box. Adding a template copies it into your own provider list. You can then edit it without changing the built-in template.

For each provider, configure:

- **Slug**: the short provider id used by the CLI, such as `github`.
- **Name**: display name.
- **Authorization endpoint**: provider authorization URL.
- **Token endpoint**: provider token URL.
- **Userinfo endpoint**: optional endpoint used to label connected accounts.
- **Scopes**: values shown as checkboxes on OAuth Connect.
- **Authorization parameters**: extra authorize URL query parameters, such as `access_type=offline` or `prompt=consent`.
- **OAuth app credentials**: client ID and client secret from the provider's developer portal.

## OAuth Connect

Use **OAuth Connect** after a provider has app credentials.

1. Select the provider.
2. Choose scopes.
3. Click **Connect**.
4. Complete the provider's browser authorization flow.
5. Return to the vault and confirm the connected account appears.

Connected OAuth accounts also appear on **Credentials**, where you can reveal an access token on demand.

## Profile and API Keys

Profile shows your vault user id and tenant id. It also manages access keys for the CLI, scripts, and agents.

Access key rules:

- The secret starts with `dwv_`.
- The full secret is shown once.
- Lost keys cannot be recovered. Delete or disable the old key and create a new one.
- Disable a key to revoke it without deleting the record.
- Delete keys that are no longer used.

## Audit Trail

The audit trail shows security-relevant events, newest first.

You can filter by event type and outcome. Typical events include token access, token refresh, token added, credential created, auth success, auth failure, and audit access.

The audit log records references such as access key name/prefix, source IP, target provider/account/name, and outcome. It does not store plaintext secret values.

