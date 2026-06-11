package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/crypto"
	"donkeywork.dev/vault-server/internal/manifests"
	"donkeywork.dev/vault-server/internal/service"
	"donkeywork.dev/vault-server/internal/store"
	"donkeywork.dev/vault-server/internal/store/memstore"
)

// TestRouterMatchesOpenAPIContract pins the chi route table to the committed OpenAPI document
// (api/openapi.json — the wire contract the CLI and SPA clients are generated from). Every
// operation in the spec must be routed, and every route must be in the spec, so neither can
// drift without the other being updated in the same change.
func TestRouterMatchesOpenAPIContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "api", "openapi.json"))
	if err != nil {
		t.Fatalf("read openapi.json: %v", err)
	}
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parse openapi.json: %v", err)
	}

	want := map[string]bool{}
	for p, ops := range spec.Paths {
		for method := range ops {
			switch m := strings.ToUpper(method); m {
			case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
				want[m+" "+p] = true
			}
		}
	}
	if len(want) == 0 {
		t.Fatal("spec parsed to zero operations — wrong path to api/openapi.json?")
	}

	got := map[string]bool{}
	err = chi.Walk(contractServer(t).router(), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		route = strings.TrimSuffix(route, "/")
		if route == "" || route == "/healthz" {
			return nil // health endpoint is deliberately not part of the public contract
		}
		got[method+" "+route] = true
		return nil
	})
	if err != nil {
		t.Fatalf("walk router: %v", err)
	}

	var missing, extra []string
	for k := range want {
		if !got[k] {
			missing = append(missing, k)
		}
	}
	for k := range got {
		if !want[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("router/spec drift:\n  in spec but not routed: %v\n  routed but not in spec: %v", missing, extra)
	}
	t.Logf("contract: %d operations verified", len(want))
}

// contractServer builds a minimal Server (memstore, no OIDC) just to materialise the route table.
func contractServer(t *testing.T) *Server {
	t.Helper()
	kek, err := crypto.NewLocalKekProvider("local:v1", map[string]string{"local:v1": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
	if err != nil {
		t.Fatal(err)
	}
	cipher := crypto.NewEnvelopeCipher(kek)
	ms := memstore.New()
	loader, err := manifests.NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	resolver := manifests.NewResolver(ms, loader)
	auditLog := audit.NewLog(16, nil, nil)
	hash := sha256.Sum256([]byte("dwv_contract"))
	_ = ms.InsertAccessKey(context.Background(), &store.AccessKey{
		UserID: uuid.New(), Name: "contract", KeyHash: hash[:], KeyPrefix: "dwv_contr",
		Scopes: []string{"vault:read"}, Enabled: true,
	})
	srv, err := NewServer(context.Background(), Deps{
		APIKeys:       service.NewAPIKeyService(ms, cipher, auditLog),
		AccessKeys:    service.NewAccessKeyService(ms, auditLog),
		OAuthConfigs:  service.NewOAuthConfigService(ms, cipher, auditLog, resolver),
		OAuthTokens:   service.NewOAuthTokenService(ms, cipher, auditLog, resolver, http.DefaultClient),
		OAuthFlow:     service.NewOAuthFlowService(ms, cipher, resolver, auditLog, http.DefaultClient, nil),
		Resolver:      resolver,
		Discovery:     manifests.NewDiscovery(http.DefaultClient),
		AuditLog:      auditLog,
		AuditQuery:    audit.NewQueryService(ms, auditLog),
		IPResolver:    audit.NewForwardedIPResolver([]string{"127.0.0.1/32"}),
		PublicBaseURL: "https://vault.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}
