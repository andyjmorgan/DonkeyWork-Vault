---
name: credential-manager
description: >-
  Retrieve and manage credentials from the DonkeyWork Vault via the `dwvault` CLI —
  API-key secrets, OAuth access tokens, and "what credentials exist + how to use them".
  Use whenever a task needs a stored secret/token (e.g. call an API, get a
  Microsoft/Google/GitHub OAuth token, fetch an API key) instead of hardcoding it.
allowed-tools: Bash(dwvault:*) Bash(~/.local/bin/dwvault:*) Bash(curl:*)
---

# credential-manager — DonkeyWork Vault credentials (via the `dwvault` CLI)

`dwvault` is a small Go client for the **DonkeyWork Vault** HTTP API. It stores
self-describing credentials (API keys + OAuth apps/tokens) encrypted at rest and
returns them on demand.

**Output discipline (important):** the requested secret/token is printed to **stdout
only**, with no decoration, so it is safe for shell substitution and never needs to be
echoed. All logs/errors go to stderr. **Never print a secret into the transcript** —
always consume it via `$(dwvault ...)` substitution.

## Installing the CLI

Use the one-line installer — it downloads the right prebuilt binary for your OS/arch,
verifies it against the published checksums, and installs it (default `~/.local/bin`):

```bash
curl -fsSL https://raw.githubusercontent.com/andyjmorgan/DonkeyWork-Vault/main/install.sh | sh
```

Keep it current with `dwvault update` (`dwvault update --check` just reports). Build from
source instead: `cd DonkeyWork-Vault/src/cli && CGO_ENABLED=0 go build -o dwvault .`

## Connecting to the vault

The vault is a plain **HTTPS** service. Point the CLI at your vault host:

```bash
export VAULT_ADDR=https://vault.donkeywork.dev   # the CLI's default; self-hosters set their own host
```

Identity is a **`dwv_` access key**, sent as the `X-Api-Key` header. Provide the key either way:

- **Env (wins over everything, never persisted):**
  ```bash
  export VAULT_API_KEY=dwv_...
  ```
- **Stored once (OS keyring, else a 0600 file), per host:**
  ```bash
  dwvault auth login            # prompts for the key (no echo), validates it against /api/v1/me
  dwvault auth status           # show the stored identity for VAULT_ADDR
  dwvault auth logout
  ```

Resolution order when no `--api-key` flag is given: `VAULT_API_KEY` → OS keyring → 0600 file.

**Getting a key:** mint one in the web UI (Access keys → create, scope `vault:readwrite`),
or with an existing key: `dwvault keys create <name> --scope vault:readwrite`. The secret
is shown **once** on creation. Scopes: `vault:read`, `vault:readwrite`, `vault:audit`.

## Commands

```bash
dwvault credentials list                 # discovery: name + truncated description + base-url + KIND
dwvault credentials get    <name>        # the secret to stdout (for $(...) substitution)
dwvault credentials shape  <name>        # JSON: kind/description/base_url/header/prefix/scheme/username/docs_url
dwvault credentials header <name>        # the ready Authorization header line (for curl -H; HTTP kinds)
dwvault credentials create <name> --secret <v> --kind <kind> [--description ..] [--base-url ..] \
                                       [--docs ..] [--header ..] [--prefix ..] [--username ..]
dwvault credentials delete <name>        # remove a stored credential

dwvault oauth list                       # connected OAuth providers (provider/account/expiry/scopes)
dwvault oauth get <provider> [--account <a>]   # a valid access token to stdout (auto-refreshed)

dwvault keys list                        # access keys (scoped auth credentials)
dwvault keys create <name> --scope vault:readwrite
dwvault keys enable|disable <id>
dwvault keys delete <id>
```

> `credentials` is the canonical group; the old `creds` shorthand still works as an alias.
> `create` is an **upsert** — re-running it for an existing name updates that credential's
> fields in place (a blank `--secret` keeps the stored secret).

### Credential kinds (`--kind`)

Every credential has an explicit **kind** — the discriminator an agent reads (in `list`/`shape`)
to know how to use the secret. Set it on `create`; it defaults to `opaque`.

| kind | meaning / how to use | key fields |
|---|---|---|
| `opaque` (default) | secret returned verbatim — HMAC secrets, tokens with no header, anything bespoke | `--secret` |
| `header_api_key` | sent as `"<header>: <prefix><secret>"` | `--header` (default Authorization), `--prefix` |
| `http_basic` | `Authorization: Basic base64(username:secret)` | `--username` (secret is the password) |
| `username_password` | a username+password login **not** sent as HTTP Basic (OAuth ROPC, DSM/query-param, DB user) | `--username` (secret is the password) |
| `ssh` | SSH login | `--username`, `--base-url ssh://host:port` (secret = password or key) |
| `connection_string` | the whole DSN is the secret; returned verbatim | `--base-url` optional |

For `header_api_key`/`http_basic`, `dwvault credentials header <name>` assembles the ready
header line. For `ssh`/`connection_string`/`opaque`, just `get` the secret (it *is* the usable
value). `--username` (without `--header`/`--prefix`) still drives HTTP Basic header assembly
regardless of kind.

## Workflow: discover → select → interpret → use

Always do this in order. Never guess a credential name or how to send it — read the
catalog first.

### 1. List what's available

```bash
dwvault credentials list      # stored credentials
dwvault oauth list            # connected OAuth providers
```

`credentials list` is a light discovery table — name, a truncated description, base URL,
and kind. It carries enough to *route* (not the full usage detail):

```
NAME          DESCRIPTION                              BASE URL                  KIND
acme-api      Acme prod REST API                       https://api.acme.com      header_api_key
backups-db    Postgres backup user                     ssh://db.acme.example     ssh
warehouse-dsn Analytics warehouse connection string    postgresql://wh.acme:5432 connection_string
```

### 2. Select the right one, then shape it

Match the **DESCRIPTION** / **BASE URL** / **KIND** to the task (e.g. "I need to call
the Acme API" → `acme-api`). The **NAME** is the identifier you pass to `shape` / `get` /
`header`. `list` is intentionally light — once you've picked one, run
`dwvault credentials shape <name>` for the full record (kind, header, prefix, username, docs_url).

### 3. Interpret the shape — header, prefix, base URL

`dwvault credentials shape <name>` returns:

| Field | Meaning / how to apply |
|---|---|
| `kind`       | How to use the secret: `opaque` / `header_api_key` / `http_basic` / `username_password` / `ssh` / `connection_string` (see the kinds table above). |
| `base_url`   | The host the secret is for — build your request URL from this. |
| `header`     | The HTTP header to put the secret in (e.g. `Authorization`, `x-api-key`). |
| `prefix`     | Goes **immediately before** the secret in that header (e.g. `Bearer ` → `Authorization: Bearer <secret>`). Often empty. |
| `scheme`     | `header` or `basic` — `basic` means it's an HTTP Basic credential (username + password). |
| `username`   | Set for Basic credentials; the secret is the password. |
| `docs_url`   | Where to read the API's auth docs if you need more. |
| `description`| Free-text — **read it**, especially when `header` is empty. |

So the rule for a normal key: send the header **`<header>: <prefix><secret>`** to a URL
under **`base_url`**.

**When `header` is empty** the secret is *not* a simple header credential — the
`description` tells you how it's used. Common cases:
- **An HMAC signing secret:** you compute an HMAC (e.g. HMAC-SHA256) of the request over
  the secret and send *that* as the API expects (e.g. an `X-Signature` header) — the
  secret itself is never sent.
- A value used as a **query param**, basic-auth pair, or by some SDK — per the description.

### 4. Use it — secret only via substitution (never printed)

```bash
# Normal header key (header + prefix + secret), built from the shape:
NAME=acme-api
read H P B < <(dwvault credentials shape "$NAME" | jq -r '"\(.header) \(.prefix) \(.base_url)"')
curl -H "$H: ${P}$(dwvault credentials get "$NAME")" "$B/health"

# Or let the CLI assemble the whole header line for you:
curl -H "$(dwvault credentials header acme-api)" https://api.acme.com/health

# OAuth: the token IS the credential; always Authorization: Bearer <token> (auto-refreshed):
TOKEN=$(dwvault oauth get microsoft) && \
  curl -H "Authorization: Bearer $TOKEN" https://graph.microsoft.com/v1.0/me
```

**Into an environment variable** (when several commands need it) — assign with `$(...)`,
then reference `"$VAR"`. Assigning does not print it; just never echo it afterwards:

```bash
export API_TOKEN="$(dwvault credentials get acme-api)"        # not printed
curl -H "Authorization: Bearer $API_TOKEN" https://api.acme.com/health
# ... more calls using "$API_TOKEN" ...
unset API_TOKEN                                               # optional: drop it when done
```

### ⚠️ Never echo the value

The secret/token must reach the process **only** via `$(...)` substitution or an env var
and **never appear in output**. This is imperative:

- ❌ `echo "$API_TOKEN"` / `echo "$(dwvault credentials get acme-api)"` / `printf %s "$SECRET"`
- ❌ putting it in a logged/visible command argument, a `--secret <value>` literal, a URL query string, a commit, a PR, or any transcript text
- ❌ `env`, `set`, `cat`-ing a file you wrote it to, or `curl -v` (headers print)
- ✅ `curl -H "Authorization: Bearer $(dwvault credentials get acme-api)" …` — used, never shown
- ✅ `export VAR="$(dwvault credentials get …)"` then reference `"$VAR"`
- ✅ pass secrets to `credentials create` via an **env var** (`SECRET=$(…) dwvault credentials create … --secret "$SECRET"`), not a literal

If you need to confirm a secret was retrieved, check a **side effect** (e.g. the API
call returned 200), not the value itself.

### Storing a new credential

```bash
# Secret via env so it isn't on the command line; set --kind so discovery is meaningful:
SECRET=$(some-source) dwvault credentials create acme-api --secret "$SECRET" --kind header_api_key \
  --description "Acme prod API" --base-url https://api.acme.com --docs https://docs.acme.com \
  --header Authorization --prefix "Bearer "

# An SSH login or a DB connection string:
PW=$(some-source) dwvault credentials create db-box --secret "$PW" --kind ssh \
  --username ops --base-url ssh://db.acme.example:22 --description "DB box SSH"
DSN=$(some-source) dwvault credentials create warehouse-dsn --secret "$DSN" --kind connection_string \
  --base-url postgresql://wh.acme:5432 --description "Analytics warehouse"
```

Before creating, `dwvault credentials list` to avoid a duplicate — `create` is an upsert, so
re-running it with the same name edits that credential. Pick the right `--kind` and fill
`description` / `base-url` / `docs` (and `header`/`prefix` or `username`) — that metadata is
exactly what the next agent reads in step 3 to know how to use it.
