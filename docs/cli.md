# CLI Guide

`dwvault` is the command-line client for DonkeyWork Vault. It is intended for shell scripts, local development, CI jobs, and agents that need credentials without embedding secrets in files.

## Install

Linux and macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/andyjmorgan/DonkeyWork-Vault/main/install.sh | sh
```

Installer environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `DWVAULT_VERSION` | `latest` | Install a specific release tag. |
| `DWVAULT_BIN_DIR` | `~/.local/bin` or `/usr/local/bin` | Install directory. |
| `DWVAULT_REPO` | `andyjmorgan/DonkeyWork-Vault` | GitHub repository to download from. |
| `DWVAULT_NO_VERIFY` | unset | Set `1` to skip checksum verification. |

Check the install:

```bash
dwvault --version
```

Upgrade later:

```bash
dwvault update
dwvault update --check
```

Set `VAULT_NO_UPDATE_CHECK=1` to disable passive update notices.

## Login

Sign in once per vault host; the CLI stores the credential and uses it for every command:

```bash
dwvault auth login
```

In an interactive terminal this shows a selector with two methods:

1. **OAuth device login** (default, recommended). The CLI prints an activation URL from the vault's identity provider. Open it in any browser, approve the request, and the CLI stores the resulting access and refresh tokens. Tokens are refreshed automatically on use.
2. **Paste API key**. Paste a `dwv_...` access key created in the web app under **Profile**. Use this for automation or anywhere browser login is impractical.

Scripts and non-interactive shells must pick a method explicitly:

```bash
dwvault auth login --oauth     # OAuth device login, no selector
dwvault auth login --api-key   # read a dwv_... key from the prompt or stdin
```

For a self-hosted vault:

```bash
dwvault --addr https://vault.example.com auth login
```

The CLI validates the credential before saving it. It stores the secret in the OS keyring when available, or in a local `0600` fallback file.

Notes:

- Already logged in to a host? Pass `--force` to replace the stored credential.
- If `VAULT_API_KEY` is set, it takes precedence over any stored login; `auth login` validates it but never stores it.
- OAuth device logins act with `vault:readwrite`; the audit scope is web-only. Mint a scoped access key instead when a caller should have narrower permissions.

Check status (shows the host, auth method, credential source, and account):

```bash
dwvault auth status
```

Forget the stored credential:

```bash
dwvault auth logout
```

## Global Options

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--addr` | `VAULT_ADDR` | `https://vault.donkeywork.dev` | Vault base URL. |
| `--api-key` | `VAULT_API_KEY` | unset | Access key for this process. Overrides stored login. |

If `--addr` has no scheme, the CLI uses `http://`. Use a full `https://...` URL for TLS.

## Credentials

List stored credentials:

```bash
dwvault credentials list
```

Print the raw secret to stdout:

```bash
dwvault credentials get grafana-prod
```

Print a complete HTTP header:

```bash
dwvault credentials header grafana-prod
```

Use it directly:

```bash
curl -H "$(dwvault credentials header grafana-prod)" https://grafana.example.com/api/health
```

Describe how to use a credential without revealing the secret:

```bash
dwvault credentials shape grafana-prod
```

Create a header API key:

```bash
dwvault credentials create grafana-prod \
  --kind header_api_key \
  --secret "$GRAFANA_TOKEN" \
  --description "Grafana production API" \
  --base-url "https://grafana.example.com" \
  --docs "https://grafana.com/docs/grafana/latest/developers/http_api/" \
  --header Authorization \
  --prefix "Bearer "
```

Create an HTTP Basic credential:

```bash
dwvault credentials create legacy-admin \
  --kind http_basic \
  --username admin \
  --secret "$PASSWORD" \
  --base-url "https://legacy.example.com"
```

Delete a credential by name:

```bash
dwvault credentials delete grafana-prod
```

## OAuth Tokens

List connected OAuth accounts:

```bash
dwvault oauth list
```

Get a valid access token:

```bash
dwvault oauth get microsoft
```

Choose one account when multiple are connected:

```bash
dwvault oauth get microsoft --account alice@example.com
```

The vault refreshes OAuth tokens when it has a refresh token and the provider allows refresh.

## Access Keys

List access keys:

```bash
dwvault keys list
```

Create a read-only key:

```bash
dwvault keys create agent-prod --scope vault:read
```

Create a key with multiple scopes:

```bash
dwvault keys create ops-admin \
  --scope vault:readwrite \
  --scope vault:audit
```

Disable, enable, or delete a key:

```bash
dwvault keys disable <id>
dwvault keys enable <id>
dwvault keys delete <id>
```

## Secret Handling

`dwvault` reserves stdout for requested secrets and tokens. Prompts, status messages, and errors go to stderr.

Prefer:

```bash
curl -H "$(dwvault credentials header grafana-prod)" "$URL"
```

Avoid:

```bash
echo "$(dwvault credentials get grafana-prod)"
curl -v -H "$(dwvault credentials header grafana-prod)" "$URL"
```

Do not put secrets in URLs, shell history, committed files, build logs, or verbose HTTP traces.

