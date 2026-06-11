#!/usr/bin/env bash
# Generate the typed clients from the committed OpenAPI document:
#   - Go  : src/cli/internal/vaultapi/vaultapi.gen.go   (oapi-codegen — models + net/http client)
#   - TS  : src/portal/frontend/src/api/schema.d.ts     (openapi-typescript — types)
#
# api/openapi.json is the hand-maintained wire contract (the Go server's contract test pins the
# route table to it). Requires: go, node/npx.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OAPI_CODEGEN_VERSION="${OAPI_CODEGEN_VERSION:-v2.4.1}"
OPENAPI_TS_VERSION="${OPENAPI_TS_VERSION:-7.4.4}"

echo "==> Go client (oapi-codegen ${OAPI_CODEGEN_VERSION})"
mkdir -p src/cli/internal/vaultapi
go run "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@${OAPI_CODEGEN_VERSION}" \
  -config api/oapi-codegen.yaml api/openapi.json

echo "==> TypeScript types (openapi-typescript ${OPENAPI_TS_VERSION})"
mkdir -p src/portal/frontend/src/api
npx --yes "openapi-typescript@${OPENAPI_TS_VERSION}" api/openapi.json -o src/portal/frontend/src/api/schema.d.ts

echo "done"
