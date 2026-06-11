# DonkeyWork Vault — Go server

A Go port of the .NET `DonkeyWork.Vault.Api` service: the REST API, OAuth flows, and (optionally)
the React SPA, backed by the **existing** Postgres `vault` schema. It is wire-compatible with the
current CLI and SPA (same camelCase JSON contract) and reads/writes the same encrypted data as the
.NET service (identical `DWV1` envelope format).

## Layout

| Package | Responsibility |
|---|---|
| `cmd/vault` | Entrypoint: config, telemetry, pool, migrations, services, audit workers, graceful shutdown |
| `internal/crypto` | AES-256-GCM envelope cipher + local KEK provider (byte-compatible with the C# `DWV1` blob) |
| `internal/store` | pgx-backed `Store` (hand-written SQL, per-user scoping, `otelpgx` query spans) + `memstore` |
| `internal/db` | Embedded SQL migrations + tiny runner (idempotent baseline; drops the EF-only tables) |
| `internal/service` | Domain logic: API keys, access keys, OAuth configs/tokens/flow (PKCE S256 + refresh) |
| `internal/manifests` | Embedded OAuth provider catalog, per-user resolver, OIDC discovery |
| `internal/audit` | Fire-and-forget sink, batch writer, retention sweeper, redactor, trusted-proxy IP resolver, query |
| `internal/httpapi` | chi router, OIDC-JWT + access-key auth, scope gate, audit/caller context, handlers |
| `internal/telemetry` | OpenTelemetry traces/metrics/logs (OTLP/HTTP) |
| `internal/contracts` | Shared caller identity + credential-kind types |

## Database

The Go service points at the **same** `vault` schema the .NET/EF service created. The baseline
migration is idempotent (`CREATE … IF NOT EXISTS`): a no-op against an existing database (all rows
retained), full provisioning on a fresh one. It also drops the two EF/framework-only tables
(`__ef_migrations_history`, `data_protection_keys`) — neither holds data the application reads.

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
