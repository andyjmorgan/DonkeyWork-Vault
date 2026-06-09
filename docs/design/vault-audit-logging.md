# Vault access & audit logging — design

> Append-only audit trail of credential-sensitive events in the DonkeyWork Vault:
> token refreshed, token added, token accessed, plus auth failures. Each event records
> source IP, the **reference** to the access key used (never the secret), and **redacted**
> request headers. Capture happens at the auth + domain-service layer so it survives the
> planned gRPC → HTTP migration.

This document is the source of truth for the milestone **"Vault access & audit logging"**.
It is grounded in the current code (gRPC over h2c, EF Core + Postgres, envelope-encrypted
secrets). Method/file references below are concrete so each task is actionable.

---

## 1. Goals & required events

Capture an append-only trail of credential-sensitive events. Required event types:

| Event | Trigger (current code) | File / method |
|---|---|---|
| **TokenRefreshed** | OAuth access token auto-refreshed via the refresh-grant path | `OAuthTokenService.RefreshAsync` (called from `GetAccessTokenAsync`) |
| **TokenAdded** | OAuth flow completed and a token row stored/updated | `OAuthFlowService.CompleteAsync` |
| **CredentialCreated** | API key / OAuth-provider-config / access-key created | `ApiKeyService.CreateAsync`, `AccessKeyService.CreateAsync`, `OAuthProviderConfigService` |
| **TokenAccessed** | A stored credential or OAuth access token read/revealed/retrieved | `ApiKeyService.GetByNameAsync` (via `CredentialStoreGrpcService.GetApiKey`); `OAuthTokenService.GetAccessTokenAsync` (via `CredentialStoreGrpcService.GetOAuthAccessToken`) |
| **AuthSucceeded** *(optional/low-signal)* | An access key authenticated | `AccessKeyService.AuthenticateAsync` |
| **AuthFailed** | Invalid/disabled key, missing scope, bad internal-token/user-id | `UserContextInterceptor` (all `Unauthenticated` / `PermissionDenied` paths) + `AuthenticateAsync` returning null |

Per event, also record: **source IP** (real client, behind k3s ingress), **access-key reference**
(id / display prefix / name — never the `dwv_` secret or its SHA-256 hash), and the
**redacted request headers**.

`TokenAccessed` is the hot path (every agent call that needs a secret hits
`CredentialStore`), so the write must be async/buffered and must never block or fail the
request.

---

## 2. Data model

### 2.1 `AuditEventType` enum (stored as `int`)

```
Unknown = 0,
TokenAccessed = 1,   // credential/OAuth access token read
TokenRefreshed = 2,  // refresh-grant produced a new access token
TokenAdded = 3,      // OAuth flow completed (token stored)
CredentialCreated = 4, // api key / access key / provider config created
AuthSucceeded = 5,
AuthFailed = 6,
AuditAccessed = 7    // someone read the audit log itself
```

### 2.2 `AuditLogEntity`

Append-only. It deliberately **does not** derive from `BaseEntity`: the per-user EF query
filter and the `UpdatedAt` mutation column are wrong for an audit table (admins must read
across users; rows must never be updated). It carries `UserId`/`TenantId` as plain columns.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` PK | `gen_random_uuid()` |
| `event_type` | `int` | `AuditEventType` |
| `outcome` | `int` | `Success = 0`, `Failure = 1` |
| `user_id` | `uuid` | subject of the event (`Guid.Empty` when auth failed before identity resolved) |
| `tenant_id` | `uuid` | |
| `access_key_id` | `uuid?` | FK-by-value to `access_keys.id`; **null** for internal-token / legacy-user-id / anonymous-callback callers |
| `access_key_prefix` | `varchar(32)?` | e.g. `dwv_AbCd` — display reference, safe |
| `access_key_name` | `varchar(255)?` | the key's friendly name |
| `source_ip` | `inet?` | resolved real client IP (see §4) |
| `headers` | `jsonb` | **redacted** request headers (see §3) |
| `target_kind` | `varchar(64)?` | `oauth_token` / `api_key` / `access_key` / `provider_config` |
| `target_provider` | `varchar(255)?` | e.g. `google`, `microsoft` |
| `target_account` | `varchar(320)?` | e.g. mailbox/email for OAuth |
| `target_name` | `varchar(255)?` | credential name |
| `transport` | `varchar(16)` | `grpc` now; `http` after migration — proves capture is transport-agnostic |
| `grpc_method` / `route` | `varchar(255)?` | `/donkeywork.vault.v1.CredentialStore/GetApiKey` |
| `detail` | `varchar(1024)?` | failure reason, e.g. `missing scope 'vault:read'` |
| `created_at` | `timestamptz` | `now()`; the event time |

**Indexes** (mirroring the access-pattern + the brief):
- `(user_id, created_at desc)` — primary admin filter.
- `(event_type, created_at desc)` — "show all refreshes".
- `(access_key_id, created_at desc)` — "what did this key do".
- `(created_at)` — retention sweep / time-range export.
- `(tenant_id, user_id)` — consistency with existing tables.

### 2.3 Migration

Add `AddAuditLog` under `src/vault/DonkeyWork.Vault.Persistence/Migrations/` following the
shape of `20260608062954_AddAccessKeys.cs`: `schema: "vault"`, snake_case columns,
`gen_random_uuid()` / `now()` defaults, the indexes above. `headers` is `jsonb`, `source_ip`
is `inet`. Register `DbSet<AuditLogEntity> AuditLogs` in `VaultDbContext` and add an
`AuditLogConfiguration : IEntityTypeConfiguration<AuditLogEntity>`. Because the snake_case +
schema loop in `OnModelCreating` runs over all entities, the new entity gets the same
treatment automatically; the only special-case is **not** attaching the BaseEntity query
filter (it isn't a `BaseEntity`).

---

## 3. Header redaction (mandatory)

Request headers carry bearer secrets. Persist headers through a **deny-by-default allowlist**:
capture only known-safe headers verbatim, redact everything else's value to `"***"` while
keeping the key (so you can see a header was present without leaking it).

- **Always redact (store key + `"***"`):** `authorization`, `x-api-key`, `x-internal-token`,
  `cookie`, `set-cookie`, `proxy-authorization`, and anything matching
  `*token*` / `*secret*` / `*password*` / `*-key`.
- **Allowlist (store verbatim):** `user-agent`, `content-type`, `accept`, `x-request-id`,
  `traceparent`, `x-forwarded-for`, `x-real-ip`, `x-forwarded-proto`, `grpc-*` framing
  headers (non-secret), `host`.
- The access key is recorded **only** as `access_key_id` + `access_key_prefix` +
  `access_key_name`. Never the `dwv_` secret, never its hash — the hash is a bearer
  equivalent for lookup and must not leak into an admin-readable table.
- Header capture is **case-insensitive**; redaction is applied before the value ever reaches
  the entity, never after.

Redaction lives in one place (`AuditHeaderRedactor`) so the allow/deny lists are auditable
and unit-tested, and both the gRPC interceptor and the future HTTP middleware use it.

---

## 4. Source IP (correct, behind ingress)

The vault sits behind k3s ingress; the socket peer is the proxy, so
`context.GetHttpContext().Connection.RemoteIpAddress` is the ingress pod IP and is **wrong**.

- Resolve the real client via `X-Forwarded-For` (left-most untrusted hop) / `X-Real-IP`,
  gated by a **trusted-proxy policy**: only honour forwarded headers when the immediate peer
  is within the configured trusted CIDR set (the ingress/service subnet, e.g. the pod/Service
  CIDR and `192.168.x` lab subnets), else fall back to the socket peer.
- Prefer ASP.NET Core `ForwardedHeadersMiddleware` (`UseForwardedHeaders` with
  `KnownNetworks`/`KnownProxies` configured) so `RemoteIpAddress` is corrected once, centrally,
  rather than re-parsing XFF in the audit code. Config-drive the trusted ranges
  (`Vault:Audit:TrustedProxies`), never hard-code.
- Store as Postgres `inet`. If resolution is ambiguous, store the socket peer and note it.

---

## 5. Capture architecture (transport-agnostic + hot-path safe)

### 5.1 `IAuditLog` abstraction (in `DonkeyWork.Vault.Contracts` or Core)

```csharp
public enum AuditOutcome { Success, Failure }

public sealed record AuditEvent(
    AuditEventType Type,
    AuditOutcome Outcome,
    Guid UserId, Guid TenantId,
    Guid? AccessKeyId, string? AccessKeyPrefix, string? AccessKeyName,
    string? SourceIp, IReadOnlyDictionary<string,string> Headers,
    string? TargetKind, string? TargetProvider, string? TargetAccount, string? TargetName,
    string Transport, string? Method, string? Detail,
    DateTimeOffset CreatedAt);

public interface IAuditLog
{
    // Non-blocking: enqueue and return. Never throws to the caller.
    void Enqueue(AuditEvent e);
}
```

`Enqueue` writes to a bounded `Channel<AuditEvent>` (`System.Threading.Channels`,
`BoundedChannelFullMode.DropWrite` or `Wait` with a tiny timeout). It **never** participates
in the request's `DbContext`/transaction and never throws — auditing must not fail or slow
the credential path.

### 5.2 `AuditLogWriter` — background `BackgroundService`

- Reads the channel, **batches** (e.g. up to 100 events or 500ms), and bulk-inserts into a
  **fresh scoped `VaultDbContext`** (not the request's) so writes never block the hot path and
  the per-user query filter is irrelevant (we insert, never read, here).
- On DB failure: retry with backoff, and as a last resort emit the event to the structured
  log sink (§9) so the trail is not silently lost. Channel back-pressure (drop-oldest with a
  dropped-count metric) prevents unbounded memory under a write outage.
- Registered as a singleton `IAuditLog` + `IHostedService` in Core DI; flushes the channel on
  graceful shutdown.

### 5.3 Request-metadata capture

A small `AuditContextAccessor` (AsyncLocal, same pattern as `VaultCallerContext`) carries the
per-request `{ SourceIp, RedactedHeaders, AccessKeyId/Prefix/Name, Transport, Method }`. It is
populated:
- **gRPC now:** in `UserContextInterceptor` — it already has `context.RequestHeaders`,
  `context.GetHttpContext()`, the resolved `AccessKeyPrincipal`, and `context.Method`. After
  resolving identity, also stash the audit context. To carry the access-key **id**, extend
  `AccessKeyPrincipal` with `Id` (and surface `KeyPrefix`) so the interceptor can record the
  reference without a second query.
- **HTTP later:** the same accessor is populated by an ASP.NET middleware — the domain
  services that emit events are unchanged, which is the whole point of capturing at this layer.

Domain services call `IAuditLog.Enqueue(...)` and read the ambient `AuditContextAccessor` for
IP/headers/key, supplying the event-specific target fields themselves.

---

## 6. Capture points (mapped to code)

- **TokenRefreshed** — `OAuthTokenService.RefreshAsync`, right after the refresh succeeds
  (`token.LastRefreshedAt = ...`). Target = `{oauth_token, provider, account}`. On
  `OAuthRefreshException`, emit `TokenRefreshed` with `Outcome=Failure` + reason in `detail`.
- **TokenAdded** — `OAuthFlowService.CompleteAsync`, after `SaveChangesAsync`. Note: this is
  the anonymous callback (`/OAuthFlow/Complete`) — identity comes from the `OAuthStateEntity`
  (`OwnerUserId`), and there is **no** access key, so `access_key_*` are null; IP/headers still
  captured. Target = `{oauth_token, provider, account}`.
- **TokenAccessed (api key)** — `ApiKeyService.GetByNameAsync` (the decrypt path), or the
  `CredentialStoreGrpcService.GetApiKey` wrapper. Emitting in the service is preferred so HTTP
  reuses it. Target = `{api_key, name}`. `Found=false` ⇒ still emit with `Outcome=Failure`.
- **TokenAccessed (oauth)** — `OAuthTokenService.GetAccessTokenAsync`. Emit on the read
  regardless of whether a refresh was needed (a refresh additionally emits TokenRefreshed —
  two events, by design). Target = `{oauth_token, provider, account}`.
- **CredentialCreated** — `ApiKeyService.CreateAsync` (distinguish create vs. edit via the
  existing `isNew`), `AccessKeyService.CreateAsync`, and `OAuthProviderConfigService` upsert.
  Never include the secret in the event.
- **AuthSucceeded / AuthFailed** — `UserContextInterceptor`: emit `AuthFailed` on every
  `Unauthenticated`/`PermissionDenied` throw (invalid/disabled key, missing scope, bad
  internal token, missing user-id) with the reason in `detail`; optionally emit `AuthSucceeded`
  for API-key callers. `AccessKeyService.AuthenticateAsync` returning null is the
  invalid/disabled-key signal.

---

## 7. Tamper-resistance & access control

- **Append-only at the app layer:** `IAuditLog` exposes only `Enqueue`; there is no update/
  delete API and `AuditLogEntity` is never tracked-then-modified. Optionally enforce in
  Postgres with a `BEFORE UPDATE/DELETE` trigger that raises, and grant the app role only
  `INSERT, SELECT` on `vault.audit_log` (retention runs as a separate privileged job/role).
- **Reading is admin-scoped:** a new `vault:audit` (read) scope, required by the query
  endpoints; not implied by `vault:readwrite`. Plain users cannot read the audit log.
- **Audit the audit:** reads of the audit log emit an `AuditAccessed` event (who/when/filter),
  so exfiltration via the admin UI is itself recorded.

---

## 8. Surfacing — portal API + UI

- **Portal REST (BFF):** add an admin-only `AuditController` in
  `src/portal/DonkeyWork.Portal.Api/Vault/` that proxies to a new vault `Audit` service
  (`Query`/`Export`) over the same internal-token hop, requiring the `vault:audit` scope.
  Filters: user, event type, access-key id, time range, outcome; cursor/paged; CSV/JSON export.
- **Frontend:** a new `src/portal/frontend/src/pages/Audit.tsx` — a filterable table (event,
  user, key prefix/name, IP, target, outcome, time) with a redacted-headers drawer and an
  export button. Follow the DonkeyWork frontend style guide (semantic tokens, existing table /
  card components, light/dark) — mirror `Credentials.tsx`.

---

## 9. Secondary sink — observability (plus)

In addition to Postgres, emit each event as a structured log record (the same redacted shape)
so it lands in the lab's **Loki** via the central otel-collector (attic cluster). This gives
ops alerting/dashboards (e.g. spike in `AuthFailed`, off-hours `TokenAccessed`) and an
out-of-band copy if the DB write path is degraded. The DB remains the authoritative,
queryable-by-key store; Loki is the streaming/alerting view. Trace correlation via
`traceparent` (already allowlisted) ties an audit event to its Tempo trace.

---

## 10. Retention & rotation

- Append-only tables grow without bound; `TokenAccessed` is high-volume. Define a retention
  window (proposed default **180 days** hot in Postgres) via a `BackgroundService`
  (`AuditRetentionJob`) that deletes `created_at < now() - interval` in batches off-peak, run
  by a privileged role (the app role is INSERT/SELECT-only).
- For longer horizons, export aged rows to cold storage (object store / Loki) before delete.
- Optionally partition `audit_log` by month (`created_at`) so retention is a partition `DROP`
  rather than a bulk `DELETE` — cheaper at volume. Make the window configurable
  (`Vault:Audit:RetentionDays`).

---

## 11. Risks & decisions

1. **Capture at the auth + domain-service layer, not gRPC plumbing.** The active direction is
   to drop gRPC for HTTP (OAuth + API key, OpenAPI models). The caller credential in scope
   here is the **API key** (`dwv_`) only — device auth flows are not built and are out of
   scope. `IAuditLog` + `AuditContextAccessor` are transport-neutral; only the
   *populator* (interceptor today, middleware tomorrow) changes. Decision: do **not** bolt
   audit onto gRPC interceptor pipeline semantics beyond reading metadata.
2. **Never block or fail the request.** Bounded channel + batched background writer; `Enqueue`
   is fire-and-forget and swallows its own errors. Risk: event loss under sustained DB outage —
   mitigated by back-pressure metrics + Loki fallback sink. Accepted trade-off: availability of
   the credential path over guaranteed durability of every audit row.
3. **Secret redaction is non-negotiable and centralised.** Deny-by-default allowlist;
   access-key stored as id/prefix/name only; the SHA-256 hash is treated as a bearer and never
   persisted to audit. One `AuditHeaderRedactor`, unit-tested, used by every populator.
4. **Source IP via ForwardedHeaders + trusted-proxy policy.** Mis-set trusted ranges would let
   a client spoof `X-Forwarded-For`; ranges are config-driven and scoped to the ingress/Service
   CIDRs. Without this, every row would show the ingress IP — useless.
5. **Append-only + admin-scoped reads + audit-the-audit.** DB-level INSERT/SELECT grant and an
   optional update/delete-blocking trigger make tampering hard even with app compromise; the
   `vault:audit` scope and `AuditAccessed` events constrain and record who reads it.
6. **Anonymous & internal-token callers have no access key.** OAuth callback (`TokenAdded`) and
   Portal-hop calls legitimately have null `access_key_*`; the schema and UI must treat null as
   first-class, not a redaction bug.

---

## Tasks (ordered)

1. **audit_log entity + EF migration** — `AuditLogEntity` + `AuditEventType`/`AuditOutcome`,
   `AuditLogConfiguration`, `DbSet`, `AddAuditLog` migration (jsonb headers, inet IP, indexes
   on user+time / event / key / time). Not a `BaseEntity` (no per-user filter, no update path).
   *AC:* migration applies; insert works; indexes present; no update/delete API on the entity.
2. **`IAuditLog` + buffered background writer** — `IAuditLog.Enqueue`, bounded
   `Channel<AuditEvent>`, `AuditLogWriter : BackgroundService` (batch insert via own scoped
   `VaultDbContext`, retry+backoff, flush on shutdown), DI registration.
   *AC:* enqueue never blocks/throws; events batch-persist; load test of TokenAccessed shows no
   added request latency; channel-full drops are counted, not fatal.
3. **Request-metadata capture (IP + header redaction)** — `AuditContextAccessor` (AsyncLocal),
   `AuditHeaderRedactor` (deny-by-default allowlist), `UseForwardedHeaders` + trusted-proxy
   config; populate from `UserContextInterceptor`. Extend `AccessKeyPrincipal` with `Id` +
   prefix.
   *AC:* `Authorization`/`x-api-key`/`x-internal-token`/`cookie` never persisted in clear;
   source IP is the real client behind ingress in a forwarded test; key recorded as
   id/prefix/name only.
4. **Emit TokenRefreshed** — in `OAuthTokenService.RefreshAsync` (success) and on
   `OAuthRefreshException` (failure). *AC:* one event per refresh with provider/account; failure
   captured with reason.
5. **Emit TokenAdded + CredentialCreated** — `OAuthFlowService.CompleteAsync` (null access key,
   identity from state row) and `ApiKeyService`/`AccessKeyService`/`OAuthProviderConfigService`
   create paths. *AC:* token-add and each credential-create produce exactly one event; no secret
   in payload; create-vs-edit distinguished.
6. **Emit TokenAccessed** — `ApiKeyService.GetByNameAsync` / `CredentialStore.GetApiKey` and
   `OAuthTokenService.GetAccessTokenAsync` / `CredentialStore.GetOAuthAccessToken`, including
   `Found=false` as Failure. *AC:* every reveal/retrieve logs one access event; a refresh-on-read
   yields both TokenAccessed and TokenRefreshed.
7. **Emit auth-failure / auth events** — `UserContextInterceptor` emits `AuthFailed` on every
   Unauthenticated/PermissionDenied path (+ optional `AuthSucceeded`); `AuthenticateAsync` null
   ⇒ invalid/disabled-key failure. *AC:* invalid key, disabled key, and missing-scope each emit
   a distinct AuthFailed with reason; identity-less failures store `Guid.Empty` user.
8. **Portal REST endpoints (admin-scoped)** — `AuditController` + vault `Audit` Query/Export
   service over the internal-token hop, gated by new `vault:audit` scope; filter by
   user/event/key/time/outcome, paged. Reads emit `AuditAccessed`. *AC:* non-admin (no
   `vault:audit`) is 403; filters work; reading the log is itself audited.
9. **Portal React audit UI** — `Audit.tsx`: filterable table + redacted-headers drawer +
   CSV/JSON export, per the frontend style guide. *AC:* filters by user/event/key/time;
   export downloads; no secret ever shown; light/dark correct.
10. **Optional Loki/otel sink** — structured-log emit of each event (redacted) to the central
    otel-collector → Loki; trace-correlate via `traceparent`. *AC:* events appear in Loki with
    redacted fields; an `AuthFailed` spike is queryable.
11. **Retention/rotation job** — `AuditRetentionJob` batched delete past
    `Vault:Audit:RetentionDays` (default 180), privileged role; optional monthly partitioning.
    *AC:* rows older than the window are removed off-peak; app role cannot delete; window is
    configurable.
12. **Tests** — unit (redactor allow/deny, IP resolution, channel back-pressure, append-only),
    integration (each capture point emits the right event with redacted headers + key ref),
    and a hot-path perf assertion for TokenAccessed. *AC:* CI green; redaction and IP cases
    covered; no secret/hash appears in any persisted row in tests.
