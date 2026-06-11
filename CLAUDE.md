# DonkeyWork Vault — Claude Project Instructions

## What this is

A self-hosted secrets vault: a single static Go binary (`src/server`, module `donkeywork.dev/vault-server`)
that serves a REST API, OAuth/PKCE flows, an audit log, and the React SPA, backed by a Postgres
`vault` schema. Stored secrets use the `DWV1` AES-256-GCM encrypted-envelope format. A companion Go
CLI (`src/cli`, module `donkeywork.dev/vault-cli`, binary `dwvault`) and the SPA both speak the
server's camelCase JSON contract. Production runs on the **attic** k3s cluster — see the deploy
section below.

## Repo structure

- `src/server` — the vault server (Go). Package responsibilities are documented in
  `src/server/README.md`; keep that table current when packages move.
- `src/cli` — the `dwvault` CLI (Go). `internal/vaultapi` is **generated** from the OpenAPI doc.
- `src/portal/frontend` — the React SPA (its API types are generated too).
- `api/openapi.json` — the hand-maintained, authoritative wire contract. The server's contract test
  pins its route table to it; the Go + TS clients are generated from it. **A contract change is not
  done until `scripts/gen-clients.sh` has regenerated the clients and they're committed** — the
  `codegen-drift` CI gate enforces this.

## Engineering standards

Standard modern Go applies (current stable, `go.mod` pins the min): `gofmt`/`goimports` clean,
`context`-first, `%w`-wrapped errors with `errors.Is`/`As`, no `panic` outside `init`, mutexes for
state and channels for communication, every goroutine bound to a `ctx`. The project-specific bits:

- **Lint** (`.golangci.yml`, shared by both modules): the enabled linters are the bar. Run
  `golangci-lint run` from each module dir before pushing. CI rejects dirty `gofmt`/`goimports`.
- **Comments** follow the global `~/.claude/CLAUDE.md` comment-hygiene rules. Go specifics: godoc
  (`//`, starting with the identifier) on every exported symbol; document sentinel errors and any
  `//nolint` / `//coverage:ignore` directive with its reason inline. Why-not-what. **Never** write
  `///` XML-doc comments — that's a .NET artifact from the predecessor.
- **Logging:** `log/slog` only. Never log secret plaintext, decrypted envelopes, or full provider
  tokens — only metadata + correlation/caller IDs. Headers are redacted through `internal/audit`.

### What we deliberately avoid

- **DI containers** — explicit constructor injection only; per-request state on `context.Context`.
- **`testify`** — stdlib `testing` is enough (table-driven `t.Run`).
- **`gomock` / `mockery`** — hand-rolled interface stubs are a few lines and clearer; the in-memory
  `store/memstore` is the canonical fake for the `Store` interface.
- **Global mutable state** — package-level vars are `const` or read-only after init. The only
  sanctioned writable package vars are the documented test seams (e.g. `randReader`,
  `initialRetentionDelay`, `githubAPIBase`), never reassigned in production.
- **`any` in public APIs** — strong typing or generics; `any` is a smell outside a serialization
  boundary.
- **Magic struct tags beyond `json` / `yaml`** — validation is explicit code, not tags.

## Dependencies

Keep the dep graph small; a new dependency needs justification in the PR description. Current direct
deps:

- **server:** `go-chi/chi` (router), `jackc/pgx` (Postgres), `coreos/go-oidc` (JWT verification),
  `google/uuid`, `gopkg.in/yaml.v3`, the OpenTelemetry SDK + OTLP/HTTP exporters.
- **cli:** `spf13/cobra` (commands), `zalando/go-keyring` (OS keychain), `oapi-codegen/runtime`
  (generated client), `golang.org/x/term`, `google/uuid`.

## Testing requirements

Unit correctness and the Postgres-integration path are both mandatory. A change that touches stored
data, SQL, or migrations is not done until the integration suite exercises it against a real
Postgres.

### Hard targets

1. **≥95% statement coverage** of hand-written code in both modules, enforced by `scripts/coverage.sh`
   in CI. The denominator **excludes** generated clients (`*.gen.go`) and `main()` entrypoints
   (`cmd/vault/main.go`, the CLI's command-dispatch files). Genuinely-unreachable defensive branches
   are tagged `//coverage:ignore <reason>` on the statement line (constructor errors on validated
   keys, `crypto/rand` failures, `embed.FS` reads, post-write `Close`/`Sync`, OS-specific branches).
   Don't tag reachable code to hit the number — write the test.
2. **Contract stays in sync.** Any change to `api/openapi.json` or a handler's shape must regenerate
   the clients (`scripts/gen-clients.sh`); the `codegen-drift` gate is release-blocking.

### Layers

| Layer | Where | How |
|---|---|---|
| Unit | `*_test.go` next to code | stdlib `testing`, table-driven `t.Run`, `memstore` as the `Store` fake |
| Integration | `internal/store`, `internal/db` | real Postgres via `VAULT_TEST_DSN` (CI starts an ephemeral container); `TestMain` provisions a fresh schema and skips when the DSN is unset |
| Contract | `internal/httpapi` contract test | pins the chi route table to `api/openapi.json` |

Run the gate locally with `bash scripts/coverage.sh [server|cli|all]`. With no `VAULT_TEST_DSN` set it
starts (and cleans up) its own ephemeral Postgres via Docker.

## PR discipline

- **Run the full surface before pushing** — per module: `gofmt -l`, `go vet ./...`,
  `golangci-lint run`, and `bash scripts/coverage.sh <module>`. Don't push hoping CI catches it.
- **`main` is protected by a required-review ruleset.** A normal merge needs an approving review;
  `gh pr merge --admin` bypasses it (admin only) and should be reserved for green-CI changes the
  author can't get a second reviewer for. Never bypass *failing* checks.
- **Confirm every state-changing action completed** — after a push, merge, image build, or cluster
  rollout, poll the resource to its terminal state and verify (CI conclusion, `rollout status`, pod
  `imageID` digest) before reporting done. A backgrounded `&& echo OK` masks the real exit code.
- PR titles/bodies follow the global `~/.claude/CLAUDE.md` rules (semantic prefix, why-first). No
  emojis in code or docs unless asked.

## Deploy (production)

attic cluster, namespace `donkeywork-vault`, deployment `vault`, image
`…/donkeywork-vault/vault:latest` (`imagePullPolicy: Always`). Public URL https://vault.donkeywork.dev.
Merging to `main` runs `docker-build.yml` (backend test + coverage gate → build `Dockerfile.vault` →
push `:latest` + sha tag). The cluster does **not** auto-redeploy `:latest`; finish with
`kubectl --context=attic -n donkeywork-vault rollout restart deployment/vault` then `rollout status`,
and verify the new pod's `imageID` digest changed. GitOps manifests live at
`/mnt/lab/k3s/clusters/attic/applications/donkeywork-vault/` — never `kubectl edit`/`patch` the
cluster; edit the YAML there and re-apply.
