#!/usr/bin/env bash
# Coverage gate for the Go modules.
#
# Computes statement coverage over hand-written code and fails if it is below the
# threshold. Conventionally-untestable code is excluded from the denominator:
#   - generated API clients (oapi-codegen output: *.gen.go)
#   - process entrypoints (cmd/vault/main.go and the CLI root command wiring)
#
# Usage:
#   scripts/coverage.sh [server|cli|all]   (default: all)
#
# A Postgres instance is required to exercise the server's store/db integration
# paths. Set VAULT_TEST_DSN, or the script will start an ephemeral container.
set -euo pipefail

THRESHOLD="${COVERAGE_THRESHOLD:-95.0}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-all}"

# Files/paths excluded from the coverage denominator. Extended-regex, matched
# against the profile's package-qualified path.
EXCLUDE_RE='\.gen\.go|cmd/vault/main\.go|vault-cli/main\.go|vault-cli/auth\.go|vault-cli/update\.go|vault-cli/skill\.go'

filtered_total() {
  # $1 = module dir, $2 = raw coverprofile. Prints coverage % over the kept blocks.
  # covfilter.py drops excluded files and //coverage:ignore blocks; go tool cover must
  # run inside the module dir to resolve package paths.
  local dir="$1" prof="$2" out modpath
  out="$(mktemp)"
  modpath="$( cd "$ROOT/$dir" && go list -m )"
  python3 "$ROOT/scripts/covfilter.py" "$prof" "$modpath" "$ROOT/$dir" "$EXCLUDE_RE" >"$out"
  ( cd "$ROOT/$dir" && go tool cover -func="$out" ) | awk '/^total:/ {print $3}'
  rm -f "$out"
}

start_pg() {
  if [[ -n "${VAULT_TEST_DSN:-}" ]]; then return; fi
  local name="vault-cov-pg-$$"
  docker run -d --name "$name" \
    -e POSTGRES_USER=vault -e POSTGRES_PASSWORD=vault -e POSTGRES_DB=vault_test \
    -p 127.0.0.1:0:5432 postgres:17-alpine >/dev/null
  trap 'docker rm -f "'"$name"'" >/dev/null 2>&1 || true' EXIT
  for _ in $(seq 1 30); do docker exec "$name" pg_isready -U vault >/dev/null 2>&1 && break; sleep 1; done
  local port
  port="$(docker port "$name" 5432/tcp | head -1 | sed 's/.*://')"
  export VAULT_TEST_DSN="postgres://vault:vault@127.0.0.1:${port}/vault_test?sslmode=disable"
}

run_module() {
  local dir="$1" name="$2" prof
  prof="$(mktemp)"
  echo "==> $name: test + coverage"
  # Explicit failure check: callers invoke run_module with `|| rc=1`, which disables `set -e`
  # for the whole function — so a failing test would otherwise be swallowed and coverage
  # computed on a partial profile. Fail loudly here instead.
  if ! ( cd "$ROOT/$dir" && go test ./... -coverpkg=./... -coverprofile="$prof" ); then
    echo "    FAIL: $name tests failed"
    rm -f "$prof"
    return 1
  fi
  local pct; pct="$(filtered_total "$dir" "$prof")"
  rm -f "$prof"
  echo "    $name: ${pct} (excluding generated + entrypoints; threshold ${THRESHOLD}%)"
  awk -v p="${pct%\%}" -v t="$THRESHOLD" 'BEGIN{exit !(p+0 >= t+0)}' || {
    echo "    FAIL: $name below ${THRESHOLD}%"; return 1; }
}

rc=0
[[ "$TARGET" == "server" || "$TARGET" == "all" ]] && { start_pg; run_module src/server server || rc=1; }
[[ "$TARGET" == "cli"    || "$TARGET" == "all" ]] && { run_module src/cli cli || rc=1; }
exit $rc
