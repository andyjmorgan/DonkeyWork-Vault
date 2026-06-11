# Go Backend Migration — Handover

This document is the complete handover for the .NET → Go migration of the DonkeyWork Vault backend.
It is written to be picked up by a coding agent (or engineer) and continued without prior context.

- **Branch:** `claude/backend-go-migration-effort-g0d00a`
- **New code:** all under `src/server` (Go module `donkeywork.dev/vault-server`, Go **1.26.4**)
- **Old code:** `src/vault` (.NET) is still present and untouched — see [C# removal](#5-remove-the-c-backend)
- **Status:** feature-complete, compiles, `go vet`/`gofmt` clean, full test suite green, smoke-tested
  against a real Postgres. **Not yet validated against live OAuth providers or a real OIDC IdP.**

> **Update 2026-06-11 — migration completed.** Validated end-to-end against a prod DB copy with
> the real Keycloak IdP and real providers (.NET-minted access-key hash verifies; secret decrypt
> parity vs the live .NET service confirmed byte-for-byte; real Google token auto-refresh; real
> Keycloak JWT → `/me`; connect-begin builds real authorize URLs + persists state). The wire
> contract is frozen as `api/openapi.json` and pinned by `internal/httpapi/contract_test.go`
> (25 operations). CI/publish workflows now build/test Go and publish from `Dockerfile.vault`
> (the Go image); the C# backend (`src/vault`, `test/`, `tools/`, solution/props/nuget files) is
> removed. TODO #2 (coverage to 95%) deliberately deferred. The remainder of this document is
> retained as historical context for the port.

---

## 1. What this is

A drop-in replacement for `DonkeyWork.Vault.Api` (the .NET service): REST API + OAuth flows +
(optionally) the React SPA, backed by the **existing** Postgres `vault` schema.

Two hard compatibility guarantees, both load-bearing — **do not break them**:

1. **Wire compatibility.** The JSON contract is identical to the .NET API (camelCase field names,
   `CredentialKind` as snake_case strings). The generated Go CLI client (`src/cli/internal/vaultapi`)
   and the React SPA must keep working with no changes.
2. **Data compatibility.** The Go service reads/writes the *same* tables and the *same* encrypted
   blobs. The envelope cipher is a byte-for-byte port of the C# `DWV1` format, so existing ciphertext
   decrypts unchanged. Existing rows are retained.

---

## 2. Architecture

```
src/server/
  cmd/vault/main.go        Entry point: config → telemetry → pgx pool → migrations → services →
                           audit workers → HTTP server → graceful shutdown.
  internal/
    config/                Env-driven config (Load()), defaults match the old appsettings.json.
    contracts/             Caller identity (threaded via context.Context) + CredentialKind enum.
    crypto/                AES-256-GCM envelope cipher + local KEK provider. DWV1 byte format.
    telemetry/             OpenTelemetry: traces+metrics+logs (OTLP/HTTP), custom instruments,
                           slog→OTLP fan-out bridge.
    store/                 pgx-backed Store interface + Postgres impl (hand-written SQL).
      memstore/            In-memory Store (unit tests + local dev).
    db/                    Embedded SQL migrations + tiny idempotent runner.
    manifests/             Embedded OAuth provider catalog (YAML), per-user resolver, OIDC discovery.
    oauth/                 PKCE helpers (S256).
    service/               Domain logic: api keys, access keys, oauth configs/tokens/flow.
    httpapi/               chi router, OIDC-JWT + access-key auth, scope gate, audit/caller
                           middleware, handlers, DTOs, scope mapper.
```

### Key design decisions (and why)

- **No ORM.** The schema is ~7 flat, CRUD-shaped tables and the secret columns are opaque ciphertext,
  so an ORM buys nothing. `store/` uses hand-written SQL over **pgx**. Each query is explicitly scoped
  to a `user_id` parameter — the Go equivalent of the C# EF per-user query filter. A handful of methods
  take an explicit *owner* id for the anonymous OAuth callback (which has no ambient caller).
- **Identity via `context.Context`.** Where the C# used AsyncLocal ambient accessors
  (`IVaultCallerContext`, `IAuditContextAccessor`), Go threads `contracts.Caller` and
  `audit.RequestInfo` through the context. Explicit, and it rides alongside the OTel span context.
- **Crypto is a faithful port.** `internal/crypto` reproduces the exact on-disk layout:
  `magic "DWV1" | version(1) | kekIdLen(1) | kekId | wrappedDekLen(2 BE) | wrappedDek | nonce(12) | tag(16) | ciphertext`,
  where `wrappedDek = nonce(12) | tag(16) | ciphertext`. Go's AES-GCM appends the tag to the
  ciphertext, so the code splits/recombines `ct||tag`. Verified by round-trip + hand-built-blob
  cross-decrypt tests in `crypto_test.go`.
- **Migrations are idempotent.** `db/migrations/0001_baseline.sql` uses `CREATE … IF NOT EXISTS`:
  a no-op against the existing EF database (all data retained), full provisioning on a fresh one.
  It also `DROP`s the two EF/framework-only tables.
- **Telemetry is wired everywhere** (see §6).

---

## 3. Database

The service points at the **same** `vault` schema EF created. Column names/types are unchanged
(mapped 1:1 in `store/types.go`).

- **Retained:** `access_keys`, `api_keys`, `audit_log`, `oauth_provider_configs`, `oauth_states`,
  `oauth_tokens`, `provider_manifests`.
- **Dropped (EF/framework-only):** `__ef_migrations_history` and `data_protection_keys`. Verified safe:
  ASP.NET DataProtection was registered but its `IDataProtector` was **never consumed** — nothing the
  app reads back was stored there (the real secret encryption is the envelope cipher).
- Migration tracking moves to `vault.schema_migrations`.

---

## 4. Configuration (environment)

Required:
- `VAULT_DSN` (or `DATABASE_URL`) — Postgres DSN
- `VAULT_CRYPTO_ACTIVE_KEK_ID` — e.g. `local:v1`
- `VAULT_CRYPTO_KEKS` — `id=base64,id2=base64` (each key 32 raw bytes / base64)

Common:
- `VAULT_LISTEN_ADDR` (default `:8080`), `VAULT_PUBLIC_BASE_URL`, `VAULT_WEBROOT` (serve SPA), `VAULT_RUN_MIGRATIONS`
- OIDC: `VAULT_OIDC_AUTHORITY`, `VAULT_OIDC_INTERNAL_AUTHORITY`, `VAULT_OIDC_AUDIENCE`,
  `VAULT_OIDC_WEB_CLIENT_ID`, `VAULT_OIDC_CLI_CLIENT_ID`, `VAULT_OIDC_WEB_SCOPES`,
  `VAULT_OIDC_CLI_SCOPES`, `VAULT_OIDC_REQUIRE_HTTPS`
- Audit: `VAULT_TRUSTED_PROXIES`, `VAULT_AUDIT_CHANNEL_CAPACITY`, `VAULT_AUDIT_BATCH_SIZE`,
  `VAULT_AUDIT_FLUSH_MS`, `VAULT_AUDIT_RETENTION_DAYS`, `VAULT_AUDIT_SWEEP_HOURS`, `VAULT_AUDIT_RETENTION_BATCH`
- Telemetry: `OTEL_EXPORTER_OTLP_ENDPOINT`, `VAULT_OTLP_INSECURE`, `VAULT_VERSION`, `VAULT_ENVIRONMENT`

Full reference: `internal/config/config.go`.

---

## 5. Telemetry (three pillars)

`internal/telemetry` installs global providers (OTLP/HTTP) when `OTEL_EXPORTER_OTLP_ENDPOINT` is set;
otherwise traces/metrics are no-ops and logs go to stderr.

- **Traces:** `otelhttp` wraps the server handler (root span) and the outbound OAuth client (token
  exchange / refresh / userinfo as child spans); `otelpgx` adds a span per SQL statement; every
  service method opens a child span (`apikey.create`, `oauthflow.complete`, …).
- **Metrics:** `vault.credential.accessed`, `vault.oauth.refreshed`, `vault.auth.attempts`,
  `vault.audit.dropped`, `vault.audit.written`, `vault.service.latency` (low-cardinality dims only).
- **Logs:** `slog` fanned out to stderr + an OTLP logs bridge (`otelslog`), trace-correlated.

Spans/logs are deliberately attribute-light: provider slugs, target kinds, outcomes — **never**
secrets, tokens, or account values.

---

## 6. Build / test / run

```bash
cd src/server
go build ./...
go vet ./... && gofmt -l .
go test ./...                                   # unit tests, no DB required
VAULT_TEST_DSN=postgres://user:pass@host/db?sslmode=disable go test ./...   # + Postgres integration
go run ./cmd/vault                              # needs the env vars in §4
```

Docker image for the Go service: `Dockerfile.vault-go` (repo root) — builds the SPA, builds a static
Go binary, serves both. The deployed image is still the C# `Dockerfile.vault` until cutover.

---

## 7. Test suite & coverage

Every package has tests; the suite is green, `gofmt`/`vet` clean. Module-wide statement coverage is
**88.8%** (`go test ./... -coverpkg=./internal/... -coverprofile … && go tool cover -func`), with
per-function coverage **94%+** on every behavioral/security package (config/oauth/contracts 100%).

Highlights:
- `crypto`: round-trip, exact blob-layout, hand-built cross-decrypt, error paths.
- `httpapi`: full HTTP integration over `memstore` (auth, scope gate, all CRUD), a JWT path using a
  fake keyset, the client-aware scope mapper, and a table-driven test that drives every handler's
  store-error (500) branch.
- `service`: OAuth begin/complete/refresh against an httptest IdP, cipher-error and network/JSON
  error paths.
- `store`: Postgres integration suite (gated by `VAULT_TEST_DSN`) covering every method + cascade +
  audit query/retention + `db.Migrate` (incl. idempotent re-run).

**The ~6% gap to 95%** is concentrated in defensive error branches, not behavior: pgx scan/exec error
paths, `db.Migrate` failure branches, `memstore`'s `FailNext` returns (test scaffolding), and
unreachable `crypto/rand` failures. To close it (see TODO #2) add a `pgxmock`-based store test and a
fault-injecting cipher/store threaded through each service call site.

---

## 8. TODO for the next agent (in priority order)

> ⚠️ Before merging/cutover, items 1 and 5 are the important ones; the rest are polish.

1. **Validate OAuth + OIDC end-to-end against real providers.** This cannot be unit-tested. Stand up
   a real OIDC IdP (Keycloak) and real Google/Microsoft/GitHub apps and verify: web JWT login, the
   CLI device-login scope mapping (`internal/httpapi/scopemap.go`), `connect` → provider → `/api/oauth/callback`
   → token stored, and auto-refresh. Confirm tokens written by the .NET service still decrypt here
   (run both against the same DB).
2. **(If a 95% gate is required) raise unit coverage.** Add `internal/store` tests using
   `github.com/pashagolub/pgxmock` for scan/exec error branches and `db.Migrate` failure paths; add a
   fault-injecting `crypto.Cipher`/`store.Store` to hit the remaining `service` error returns. ~138
   statements; estimate 2–3 test files.
3. **Regenerate the OpenAPI doc + clients from the Go server.** Today `api/openapi.json` is emitted by
   the C# app and drives `src/cli/internal/vaultapi/*.gen.go` and the SPA's `schema.d.ts`. Pick a Go
   OpenAPI source (annotations or a hand-maintained spec), regenerate, and diff against the current
   `api/openapi.json` to prove the contract is unchanged. **Until then, treat the existing
   `api/openapi.json` as the contract and do not change DTO JSON tags.**
4. **CI + SessionStart hook.** Add a workflow that runs `go build/vet/test` (with an ephemeral
   Postgres service for the integration suite) and a `.claude` SessionStart hook so web sessions can
   run the suite.
5. **Cutover & remove the C# backend.** Once 1 is green in a real environment: switch the deployment to
   `Dockerfile.vault-go`, then delete `src/vault`, `test/`, `tools/`, `DonkeyWork.Vault.slnx`,
   `Directory.Build.props`, `global.json`, `*nuget.config`, and `Dockerfile.vault`. Update the root
   `README.md` "Repository layout" / "Build & develop" sections. (Left in place deliberately so parity
   can be checked side-by-side.)

---

## 9. Invariants — DO NOT BREAK

1. **Crypto format.** Don't change the `DWV1` byte layout or the KEK-wrap layout. Existing ciphertext
   must keep decrypting. If you add a KEK, add it alongside (rotation is append-only; the kekId travels
   in the blob).
2. **Wire contract.** Don't rename DTO JSON tags or change `CredentialKind` string values — the CLI and
   SPA depend on them. Keep camelCase.
3. **Per-user scoping.** Every store query is scoped by `user_id`. The only deliberate exceptions take
   an *explicit owner id* (OAuth callback / `IgnoreQueryFilters` equivalents). Don't add an unscoped query.
4. **Auditing never blocks or fails the credential path.** `audit.Log.Enqueue` is non-blocking and
   drops-with-a-counter under back-pressure. The writer runs on its own goroutine/DB handle.
5. **No secrets in logs/spans/audit.** Audit stores key references (id/prefix/name) and redacted
   headers only — never the `dwv_` secret, its hash, tokens, or client secrets. Keep it that way.
6. **DB tables are shared with (a possibly still-running) .NET service** until cutover — additive,
   compatible schema changes only.

---

## 10. Commit map on this branch

1. crypto, contracts, telemetry foundation
2. store (pgx), migrations, manifests, audit subsystem
3. domain services (api keys, access keys, OAuth)
4. HTTP API (chi), OIDC + access-key auth, main wiring
5. memstore + first unit tests (+ audit shutdown-drain fix)
6. rebase onto main + port the OAuth device-login parity (scope mapper, AppConfig fields)
7. full test suite, `Dockerfile.vault-go`, `src/server/README.md`
8. this handover doc
