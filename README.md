# DonkeyWork Vault

A small, self-hostable **credential vault** for humans and agents. It stores API keys and
OAuth tokens encrypted at rest, describes *how each credential is used*, and hands them out
on demand — over a gRPC API, a web console, and a single-binary CLI (`dwvault`).

The design goal is **agent-friendly credential discovery**: a credential isn't an opaque
secret, it's *self-describing* (name, description, base URL, docs link, header, prefix), so
an automated caller can list what exists, learn how to apply each one, and retrieve the
secret only at the moment of use — without it ever being printed.

---

## Contents

- [Architecture](#architecture)
- [Components](#components)
- [Security model](#security-model)
- [Install the CLI](#install-the-cli)
- [Using the CLI](#using-the-cli)
- [The Portal](#the-portal)
- [Credential model](#credential-model)
- [Repository layout](#repository-layout)
- [Build & develop](#build--develop)
- [Deploying](#deploying)
- [Roadmap](#roadmap)

---

## Architecture

```
                 ┌─────────────────┐
   browser ────▶ │  Portal (SPA +  │ ── gRPC ─┐
  (Keycloak)     │  BFF, 1 image)  │          │
                 └─────────────────┘          ▼
                                       ┌───────────────┐     ┌────────────┐
   terminal ───── gRPC (h2c) ────────▶ │  Vault (gRPC) │ ──▶ │ PostgreSQL │
   dwvault CLI                         │  envelope enc │     │ (ciphertext)│
                                       └───────────────┘     └────────────┘
```

- **Vault** — gRPC service; the only thing that can decrypt. Envelope-encrypts every secret
  before it touches the database.
- **Portal** — a React SPA + a thin backend-for-frontend in one container; authenticates
  users with **your** Keycloak (JWT) and talks to the Vault over gRPC.
- **dwvault** — a dependency-free Go CLI that retrieves credentials for shell/agent use.

## Components

| Path | What |
|---|---|
| `src/vault/` | The gRPC Vault: crypto, persistence (EF Core + Postgres), credential + OAuth services. |
| `src/portal/` | `DonkeyWork.Portal.Api` (BFF) + `frontend/` (Vite + React + Tailwind SPA). |
| `src/cli/` | `dwvault` — the Go credential CLI. |
| `src/proto/` | The shared `vault.proto` (gRPC contract for .NET + Go). |

## Security model

- **Envelope encryption.** Each secret gets a per-row data key (DEK); the value is sealed
  with **AES-256-GCM**, and the DEK is wrapped by a key-encryption key (KEK). The stored
  blob is self-describing (`magic | version | kekId | wrappedDek | nonce | tag | ciphertext`)
  so keys can be rotated.
- **The database only ever holds ciphertext.** Decryption happens in the Vault process.
- **Secret-to-stdout discipline.** The CLI prints a secret to **stdout only**, with no
  decoration, so it's safe for `$(...)` substitution and never needs to be echoed. Logs and
  errors go to stderr.
- **Auth.** The Portal trusts JWTs from your Keycloak realm. OAuth connect uses the
  authorization-code flow with **PKCE (S256)**; one-time state + PKCE verifier are stored
  server-side and consumed on callback.

## Install the CLI

Prebuilt binaries are published on every release for **linux** and **darwin**, `amd64` and
`arm64`. Download the one for your platform from the latest release:

```bash
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m); case "$arch" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; esac
curl -fsSL -o dwvault \
  "https://github.com/andyjmorgan/DonkeyWork-Vault/releases/latest/download/dwvault-$os-$arch"
chmod +x dwvault
install -Dm755 dwvault ~/.local/bin/dwvault    # or: sudo mv dwvault /usr/local/bin/
dwvault --version
```

Verify the download against the published checksums:

```bash
curl -fsSL -O "https://github.com/andyjmorgan/DonkeyWork-Vault/releases/latest/download/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing
```

Collaborators can also use `gh`:

```bash
gh release download -R andyjmorgan/DonkeyWork-Vault -p "dwvault-$os-$arch"
```

> **macOS:** the binaries are not yet code-signed, so a *browser* download is
> Gatekeeper-quarantined. The `curl` install above avoids that; if needed,
> `xattr -d com.apple.quarantine dwvault`. (Signing + notarization is on the roadmap.)

## Using the CLI

Point it at your Vault and identify yourself (env or flags):

```bash
export VAULT_ADDR=your-vault-host:8080        # the Vault gRPC endpoint (h2c)
export VAULT_USER_ID=<your-user-id>           # sent as x-user-id metadata
# export VAULT_TENANT_ID=<tenant>             # optional
```

Commands:

```bash
dwvault creds list                 # every API key + how to use it (header/prefix/base-url/docs)
dwvault creds get   <name>         # the secret to stdout (for $(...) substitution)
dwvault creds shape <name>         # JSON: description/base_url/header/prefix/docs_url
dwvault creds create <name> --secret <v> [--description ..] [--base-url ..] [--docs ..] [--header ..] [--prefix ..]

dwvault oauth list                 # connected OAuth providers (provider/account/expiry/scopes)
dwvault oauth token <provider> [--account <a>]   # a valid access token to stdout (auto-refreshed)
```

**Workflow: discover → select → interpret → use.** Read `creds list` / `creds shape` to learn
which header + prefix + base URL a credential needs, then `get` it only at call time:

```bash
# Build the call from the credential's own shape — secret never printed:
curl -H "Authorization: Bearer $(dwvault creds get grafana)" https://grafana.example.com/api/health

# OAuth (auto-refreshed) access token:
TOKEN=$(dwvault oauth token microsoft) && \
  curl -H "Authorization: Bearer $TOKEN" https://graph.microsoft.com/v1.0/me
```

> **Never echo the value.** Use it via `$(...)` or an env var; don't `echo` it, put it in a
> visible command argument, a URL query, `curl -v`, or any committed/printed text. Confirm
> success by a side effect (e.g. HTTP 200), not by printing the secret.

## The Portal

A web console (served at your chosen host, authenticated via Keycloak) to:

- **Credentials** — add/edit/delete self-describing API keys; reveal a stored secret or a
  live OAuth access token on demand; see connected OAuth accounts.
- **Providers** — add custom OAuth providers via **OIDC discovery** (paste an issuer URL,
  endpoints are fetched from `.well-known/openid-configuration`); built-ins are read-only.
- **OAuth Connect** — brand provider cards; enter your OAuth app's client id/secret, pick
  scopes from a described catalog (with *sensitive* flags), and connect via browser redirect.

## Credential model

- **API keys are free-form and self-describing** — `name`, `description`, `base_url`,
  `docs_url`, `header` (optional), `prefix` (optional), and the secret. There's no fixed
  "provider type"; the metadata is what tells a caller how to use the key.
- **OAuth** — built-in manifests for Google / Microsoft / GitHub plus custom OIDC providers;
  per-user app configs (client id/secret) and tokens are envelope-encrypted; tokens are
  auto-refreshed on retrieval.

## Repository layout

```
src/vault/      gRPC Vault (.NET): Api, Core, Persistence, Contracts
src/portal/     Portal: DonkeyWork.Portal.Api (BFF) + frontend/ (React SPA)
src/cli/        dwvault Go CLI
src/proto/      vault.proto (shared gRPC contract)
test/           integration tests
tools/          maintenance utilities (e.g. importer)
Dockerfile.vault, Dockerfile.portal
```

## Build & develop

Requirements: **.NET 10 SDK**, **Go 1.24+**, **Node 22+** (for the SPA).

```bash
# backend (vault + portal + tests)
dotnet build DonkeyWork.Vault.slnx

# CLI
cd src/cli && CGO_ENABLED=0 go build -o dwvault .

# SPA
cd src/portal/frontend && npm ci && npm run build
```

The gRPC stubs are generated from `src/proto/.../vault.proto` (Grpc.Tools for .NET;
`protoc` + `protoc-gen-go`/`protoc-gen-go-grpc` for the CLI).

## Deploying

Both services ship as containers (`Dockerfile.vault`, `Dockerfile.portal`). The Vault
serves gRPC over **h2c on 8080** and a health endpoint on **8081**; it runs EF Core
migrations on start. Provide via configuration:

- `Vault:Persistence:ConnectionString` — Postgres.
- `Vault:Crypto:ActiveKekId` + `Vault:Crypto:Keks:<id>` — the KEK(s).
- Portal: `Vault:GrpcEndpoint`, `Keycloak:Authority` + `Keycloak:Audience`, and
  `Portal:PublicBaseUrl` (used to build OAuth redirect URIs).

You bring your own public DNS and identity provider, and register
`https://<your-host>/api/oauth/{provider}/callback` as an allowed redirect URI on each
OAuth app you connect.

### Bring your own identity provider (JWT / OIDC)

The Portal authenticates users with **standard OIDC bearer JWTs** — it isn't tied to a
specific vendor (the config section is just named `Keycloak` for historical reasons). Any
OIDC-compliant IdP works on the **backend** (Keycloak, Microsoft Entra ID, Auth0, Okta,
Cognito, Authentik, Zitadel, …):

| Setting | Meaning |
|---|---|
| `Keycloak:Authority` | Your issuer URL. The BFF fetches `<authority>/.well-known/openid-configuration` for keys; the issuer is validated against this. Leave **blank to disable auth** (local/dev only). |
| `Keycloak:Audience`  | Your API/client audience. |
| `Keycloak:InternalAuthority` | Optional — issuer URL reachable from inside the cluster, if it differs from the public one (metadata is fetched from here). |
| `Keycloak:RequireHttpsMetadata` | Defaults to `true`. |

Tokens are validated by **signature + issuer via JWKS** (audience validation is currently
off — tighten if your IdP sets a stable `aud`). The BFF reads two claims and forwards them
to the Vault: **`sub` → the user id**, and optional **`tenant_id` → the tenant**. So your
IdP must issue a stable `sub`, and a `tenant_id` claim if you use tenancy.

> **Frontend caveat:** the SPA login is currently implemented with **`keycloak-js`** (and a
> hardcoded realm/client). The *backend* is generic OIDC, but to log in against a non-Keycloak
> IdP you must either (a) put a Keycloak in front that federates your IdP, or (b) swap the SPA's
> `keycloak-js` for a generic OIDC client (e.g. `oidc-client-ts`) — a small, isolated change.
> Making the SPA IdP-agnostic is a tracked follow-up.

A tagged release (`vX.Y.Z`) also cross-compiles and publishes the `dwvault` binaries via the
`release-cli` GitHub Actions workflow.

## Roadmap

- **HTTP Basic + SSH-key credentials** (user:password logins; SSH/git auth).
- **Browserless device registration** for the CLI (OAuth 2.0 Device Grant, RFC 8628) to
  replace the manual `VAULT_USER_ID`.
- **Public distribution polish** — `install.sh`, a Homebrew tap, and **Apple code signing +
  notarization** so the macOS binaries run without a Gatekeeper prompt.
