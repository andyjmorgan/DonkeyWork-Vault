# DonkeyWork Vault — Go server

The DonkeyWork Vault server: a single static Go binary (module `donkeywork.dev/vault-server`) that
serves the REST API, OAuth flows, and the React SPA, backed by a Postgres `vault` schema. The CLI
and SPA speak its camelCase JSON contract, and stored secrets use the `DWV1` encrypted envelope
format.

## Layout

| Package | Responsibility |
|---|---|
| `cmd/vault` | Entrypoint: config, telemetry, pool, migrations, services, audit workers, graceful shutdown |
| `internal/crypto` | AES-256-GCM envelope cipher + local KEK provider (the `DWV1` blob format) |
| `internal/store` | pgx-backed `Store` (hand-written SQL, per-user scoping, `otelpgx` query spans) + `memstore` |
| `internal/db` | Embedded SQL migrations + tiny runner (idempotent baseline) |
| `internal/service` | Domain logic: API keys, access keys, OAuth configs/tokens/flow (PKCE S256 + refresh) |
| `internal/manifests` | Embedded OAuth provider catalog, per-user resolver, OIDC discovery |
| `internal/audit` | Fire-and-forget sink, batch writer, retention sweeper, redactor, trusted-proxy IP resolver, query |
| `internal/httpapi` | chi router, OIDC-JWT + access-key auth, scope gate, audit/caller context, handlers |
| `internal/telemetry` | OpenTelemetry traces/metrics/logs (OTLP/HTTP) |
| `internal/contracts` | Shared caller identity + credential-kind types |

## Database

The server owns the `vault` schema. The baseline migration is idempotent (`CREATE … IF NOT EXISTS`):
it fully provisions a fresh database and is a no-op against an existing one (all rows retained).
Migrations are embedded and run on startup unless `VAULT_RUN_MIGRATIONS=false`.

## Configuration (environment)

Required: `VAULT_DSN`, `VAULT_CRYPTO_ACTIVE_KEK_ID`, `VAULT_CRYPTO_KEKS` (`id=base64,…`).
Common: `VAULT_LISTEN_ADDR`, `VAULT_PUBLIC_BASE_URL`, `VAULT_WEBROOT`, `VAULT_OIDC_AUTHORITY`,
`VAULT_OIDC_WEB_CLIENT_ID`, `VAULT_OIDC_CLI_CLIENT_ID`, `VAULT_TRUSTED_PROXIES`,
`OTEL_EXPORTER_OTLP_ENDPOINT` (+ `VAULT_OTLP_INSECURE`). See `internal/config`.

## Build, test, run

```bash
cd src/server
go build ./...
go test ./...                         # unit tests (no DB needed)
VAULT_TEST_DSN=postgres://… go test ./...   # also runs the Postgres integration tests
go run ./cmd/vault
```

## Telemetry

All three OTel pillars are wired: HTTP server + outbound OAuth client spans (`otelhttp`), DB query
spans (`otelpgx`), per-service-method spans, custom metrics (credential access, token refresh, auth
outcomes, audit drops/writes), and an slog→OTLP logs bridge. Without `OTEL_EXPORTER_OTLP_ENDPOINT`
it logs to stderr and traces/metrics are no-ops.
