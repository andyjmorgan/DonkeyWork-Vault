# Quick Start

This guide gets you from an empty vault to a working CLI call.

## 1. Sign in

Open the hosted vault:

```text
https://vault.donkeywork.dev
```

For a self-hosted vault, open your own public URL instead.

## 2. Add a Credential

Go to **Credentials** and use the **+** button.

Choose **API key / token** for header-based credentials such as bearer tokens, service tokens, or API keys.

Choose **Username + password** for HTTP Basic credentials.

Recommended fields:

- **Name**: a short script-safe name, such as `grafana-prod` or `github-ci`.
- **Secret**: the token, API key, password, DSN, or other secret value.
- **Description**: what the credential unlocks and when it should be used.
- **Base URL / host**: the service URL where the credential applies.
- **API docs link**: provider documentation for callers and agents.
- **Header**: commonly `Authorization`, `X-Api-Key`, or the provider-specific header.
- **Prefix**: commonly `Bearer `, including the trailing space.

## 3. Install the CLI

Linux and macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/andyjmorgan/DonkeyWork-Vault/main/install.sh | sh
dwvault --version
```

## 4. Log In

Hosted vault:

```bash
dwvault auth login
```

Self-hosted vault:

```bash
dwvault --addr https://vault.example.com auth login
```

**OAuth device login** is the default: the CLI prints an activation URL, you approve it in a browser, and the access/refresh tokens are stored in your OS keyring (or a `0600` file). No key to copy.

Choose **Paste API key** in the selector (or run `dwvault auth login --api-key`) if you prefer a `dwv_...` access key — see the next step for minting one.

## 5. Optional: Mint an Access Key for Automation

For unattended scripts, CI jobs, or agents where browser login is impractical, go to **Profile** in the web app and create an API key.

Pick the least scope needed:

| Scope | Use |
|---|---|
| `vault:read` | Read credentials and OAuth tokens. Best default for scripts. |
| `vault:readwrite` | Create, update, and delete vault records. |
| `vault:audit` | Read audit events. |

The key value starts with `dwv_` and is shown once. Copy it immediately. Store it with `dwvault auth login --api-key`, or pass it per-process via `VAULT_API_KEY`.

## 6. Use a Credential

List credentials:

```bash
dwvault credentials list
```

Inspect how a credential should be used:

```bash
dwvault credentials shape grafana-prod
```

Use a ready-made header with `curl`:

```bash
curl -H "$(dwvault credentials header grafana-prod)" https://grafana.example.com/api/health
```

Fetch only the raw secret:

```bash
TOKEN="$(dwvault credentials get grafana-prod)"
```

Do not echo secrets or paste them into logs. Prefer command substitution or environment variables scoped to the process that needs them.

