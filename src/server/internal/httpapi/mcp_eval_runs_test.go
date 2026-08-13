package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/service"
)

func TestMCPEvalRunHandlers(t *testing.T) {
	h := newHarness(t)
	connection := createMCPConnection(t, h, "https://example.com/mcp")
	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	rec := h.do(t, http.MethodPost, "/api/v1/mcp/eval-runs", createMCPEvalRunRequest{
		RunID: "eval-20260813-001", ConnectionIDs: []uuid.UUID{connection.ID}, ExpiresAt: expiresAt,
	}, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create eval run %d: %s", rec.Code, rec.Body)
	}
	created := decode[createdMCPEvalRunResponse](t, rec)
	if created.RunID != "eval-20260813-001" || created.AccessKeyID == uuid.Nil || !strings.HasPrefix(created.Secret, service.SecretPrefix) {
		t.Fatalf("created eval run: %+v", created)
	}
	if len(created.Connections) != 1 || created.Connections[0].ID != connection.ID || created.Connections[0].ProxyURL != "https://vault.example/api/v1/mcp/proxy/example" {
		t.Fatalf("created connections: %+v", created.Connections)
	}
	principal, err := h.server.deps.AccessKeys.Authenticate(t.Context(), created.Secret)
	if err != nil || principal == nil || len(principal.Scopes) != 1 || principal.Scopes[0] != "vault:mcp" {
		t.Fatalf("eval credential: %+v %v", principal, err)
	}

	runs := decode[[]mcpEvalRunDTO](t, h.do(t, http.MethodGet, "/api/v1/mcp/eval-runs", nil, true))
	if len(runs) != 1 || runs[0].ID != created.ID || runs[0].RevokedAt != nil {
		t.Fatalf("list eval runs: %+v", runs)
	}
	if strings.Contains(h.do(t, http.MethodGet, "/api/v1/mcp/eval-runs", nil, true).Body.String(), created.Secret) {
		t.Fatal("list exposed show-once secret")
	}

	if revoke := h.do(t, http.MethodDelete, "/api/v1/mcp/eval-runs/"+created.ID.String(), nil, true); revoke.Code != http.StatusNoContent {
		t.Fatalf("revoke eval run %d: %s", revoke.Code, revoke.Body)
	}
	principal, err = h.server.deps.AccessKeys.Authenticate(t.Context(), created.Secret)
	if err != nil || principal != nil {
		t.Fatalf("revoked credential authenticated: %+v %v", principal, err)
	}
	runs = decode[[]mcpEvalRunDTO](t, h.do(t, http.MethodGet, "/api/v1/mcp/eval-runs", nil, true))
	if len(runs) != 1 || runs[0].RevokedAt == nil {
		t.Fatalf("revoked list: %+v", runs)
	}
}

func TestMCPEvalRunHandlerErrors(t *testing.T) {
	h := newHarness(t)
	tests := []struct {
		name   string
		method string
		path   string
		body   any
		status int
	}{
		{name: "invalid body", method: http.MethodPost, path: "/api/v1/mcp/eval-runs", status: http.StatusBadRequest},
		{name: "invalid id", method: http.MethodDelete, path: "/api/v1/mcp/eval-runs/not-a-uuid", status: http.StatusBadRequest},
		{name: "missing", method: http.MethodDelete, path: "/api/v1/mcp/eval-runs/" + uuid.NewString(), status: http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var rec *httptest.ResponseRecorder
			if test.name == "invalid body" {
				req := httptest.NewRequest(test.method, test.path, strings.NewReader("{"))
				req.Header.Set("X-Api-Key", h.secret)
				rec = httptest.NewRecorder()
				h.h.ServeHTTP(rec, req)
			} else {
				rec = h.do(t, test.method, test.path, test.body, true)
			}
			if rec.Code != test.status {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestMCPEvalRunHandlerValidation(t *testing.T) {
	h := newHarness(t)
	connection := createMCPConnection(t, h, "https://example.com/mcp")
	tests := []createMCPEvalRunRequest{
		{RunID: "", ConnectionIDs: []uuid.UUID{connection.ID}, ExpiresAt: time.Now().Add(time.Hour)},
		{RunID: "run", ConnectionIDs: nil, ExpiresAt: time.Now().Add(time.Hour)},
		{RunID: "run", ConnectionIDs: []uuid.UUID{connection.ID}, ExpiresAt: time.Now().Add(25 * time.Hour)},
	}
	for _, request := range tests {
		rec := h.do(t, http.MethodPost, "/api/v1/mcp/eval-runs", request, true)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid request returned %d: %s", rec.Code, rec.Body)
		}
	}
	if runs := decode[[]mcpEvalRunDTO](t, h.do(t, http.MethodGet, "/api/v1/mcp/eval-runs", nil, true)); len(runs) != 0 {
		t.Fatalf("invalid requests persisted runs: %+v", runs)
	}
}
