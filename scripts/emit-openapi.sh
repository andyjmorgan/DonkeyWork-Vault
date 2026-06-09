#!/usr/bin/env bash
# Emit the authoritative OpenAPI document for the vault HTTP API.
#
# The .NET endpoints ARE the contract: we run the service with migrations disabled (no database
# needed), scrape /openapi/v1.json, and normalise it (drop the env-specific `servers` block, sort
# keys) so the committed api/openapi.json is reproducible byte-for-byte by the drift gate.
#
# Requires: dotnet 10 SDK, jq, curl. Run from anywhere.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT="${OPENAPI_PORT:-8088}"
export Vault__RunMigrationsOnStartup=false
export Vault__Persistence__ConnectionString="${Vault__Persistence__ConnectionString:-Host=localhost;Database=vault;Username=vault;Password=x}"
export ASPNETCORE_ENVIRONMENT=Production

dotnet run --project src/vault/DonkeyWork.Vault.Api/DonkeyWork.Vault.Api.csproj \
  --no-launch-profile -c Release --urls "http://127.0.0.1:${PORT}" >/tmp/vault-openapi-run.log 2>&1 &
APP=$!
trap 'kill "$APP" 2>/dev/null || true' EXIT

for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${PORT}/openapi/v1.json" -o /tmp/openapi.raw.json 2>/dev/null; then
    break
  fi
  sleep 1
done

if [ ! -s /tmp/openapi.raw.json ]; then
  echo "failed to fetch /openapi/v1.json" >&2
  tail -30 /tmp/vault-openapi-run.log >&2 || true
  exit 1
fi

mkdir -p "$ROOT/api"
jq -S 'del(.servers)' /tmp/openapi.raw.json > "$ROOT/api/openapi.json"
echo "wrote api/openapi.json"
