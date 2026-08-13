package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/mcp"
	"donkeywork.dev/vault-server/internal/service"
	"donkeywork.dev/vault-server/internal/store"
)

func createMCPConnection(t *testing.T, h *harness, upstream string) mcpConnectionDTO {
	t.Helper()
	enabled := true
	rec := h.do(t, http.MethodPost, "/api/v1/mcp/connections", upsertMCPConnectionRequest{
		Slug: "example", Name: "Example", UpstreamURL: upstream, AuthMode: "none", AuditMode: "redacted", Enabled: &enabled,
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("create MCP %d: %s", rec.Code, rec.Body)
	}
	return decode[mcpConnectionDTO](t, rec)
}

func TestMCPConfigurationHandlers(t *testing.T) {
	h := newHarness(t)
	connection := createMCPConnection(t, h, "https://example.com/mcp")
	if connection.UpstreamProtocolMode != "modern_2026_07" || connection.LegacyProtocolVersion != "2025-06-18" {
		t.Fatalf("default upstream protocol config: %+v", connection)
	}
	if rows := decode[[]mcpConnectionDTO](t, h.do(t, http.MethodGet, "/api/v1/mcp/connections", nil, true)); len(rows) != 1 {
		t.Fatal("list")
	}
	connection.Name = "Updated"
	rec := h.do(t, http.MethodPut, "/api/v1/mcp/connections/"+connection.ID.String(), upsertMCPConnectionRequest{Slug: connection.Slug, Name: connection.Name, UpstreamURL: connection.UpstreamURL, AuthMode: "headers", AuditMode: "metadata", UpstreamProtocolMode: "legacy_session", LegacyProtocolVersion: "2025-11-25", Enabled: boolPtr(true)}, true)
	updated := decode[mcpConnectionDTO](t, rec)
	if rec.Code != http.StatusOK || updated.Name != "Updated" || updated.UpstreamProtocolMode != "legacy_session" || updated.LegacyProtocolVersion != "2025-11-25" {
		t.Fatal("update")
	}
	if rec := h.do(t, http.MethodPost, "/api/v1/mcp/connections", upsertMCPConnectionRequest{Slug: "invalid-mode", Name: "Invalid", UpstreamURL: "https://example.com/mcp", AuthMode: "none", AuditMode: "redacted", UpstreamProtocolMode: "future", Enabled: boolPtr(true)}, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid upstream protocol mode: %d %s", rec.Code, rec.Body)
	}
	if rec := h.do(t, http.MethodPost, "/api/v1/mcp/connections", upsertMCPConnectionRequest{Slug: "invalid-version", Name: "Invalid", UpstreamURL: "https://example.com/mcp", AuthMode: "none", AuditMode: "redacted", LegacyProtocolVersion: "2024-01-01", Enabled: boolPtr(true)}, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid legacy protocol version: %d %s", rec.Code, rec.Body)
	}
	if rec := h.do(t, http.MethodPut, "/api/v1/mcp/connections/bad", map[string]string{}, true); rec.Code != 400 {
		t.Fatal("bad id")
	}

	key := &store.AccessKey{UserID: h.userID, Name: "eval", KeyHash: []byte("other"), KeyPrefix: "dwv_eval", Scopes: []string{"vault:mcp"}, Enabled: true}
	if err := h.ms.InsertAccessKey(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	rec = h.do(t, http.MethodPost, "/api/v1/mcp/connections/"+connection.ID.String()+"/grants", createMCPGrantRequest{AccessKeyID: key.ID}, true)
	if rec.Code != 200 {
		t.Fatalf("grant %d %s", rec.Code, rec.Body)
	}
	grant := decode[mcpGrantDTO](t, rec)
	if rows := decode[[]mcpGrantDTO](t, h.do(t, http.MethodGet, "/api/v1/mcp/connections/"+connection.ID.String()+"/grants", nil, true)); len(rows) != 1 {
		t.Fatal("grants")
	}
	if rec := h.do(t, http.MethodDelete, "/api/v1/mcp/grants/"+grant.ID.String(), nil, true); rec.Code != 204 {
		t.Fatal("delete grant")
	}

	secret, err := h.cipher.EncryptString("upstream-secret")
	if err != nil {
		t.Fatal(err)
	}
	header := "X-Upstream"
	credential := &store.APIKey{UserID: h.userID, Name: "upstream", FieldsCipher: secret, Kind: "header_api_key", HeaderName: &header}
	if err := h.ms.InsertAPIKey(t.Context(), credential); err != nil {
		t.Fatal(err)
	}
	rec = h.do(t, http.MethodPost, "/api/v1/mcp/connections/"+connection.ID.String()+"/headers", createMCPHeaderBindingRequest{CredentialID: credential.ID}, true)
	if rec.Code != 200 {
		t.Fatalf("header %d %s", rec.Code, rec.Body)
	}
	binding := decode[mcpHeaderBindingDTO](t, rec)
	if rows := decode[[]mcpHeaderBindingDTO](t, h.do(t, http.MethodGet, "/api/v1/mcp/connections/"+connection.ID.String()+"/headers", nil, true)); len(rows) != 1 {
		t.Fatal("headers")
	}
	if rec := h.do(t, http.MethodDelete, "/api/v1/mcp/headers/"+binding.ID.String(), nil, true); rec.Code != 204 {
		t.Fatal("delete header")
	}

	rec = h.do(t, http.MethodPut, "/api/v1/mcp/connections/"+connection.ID.String()+"/policies", upsertMCPToolPolicyRequest{Method: "tools/call", ToolName: "allowed", Allow: true}, true)
	if rec.Code != 200 {
		t.Fatalf("policy %d %s", rec.Code, rec.Body)
	}
	policy := decode[mcpToolPolicyDTO](t, rec)
	if rows := decode[[]mcpToolPolicyDTO](t, h.do(t, http.MethodGet, "/api/v1/mcp/connections/"+connection.ID.String()+"/policies", nil, true)); len(rows) != 1 {
		t.Fatal("policies")
	}
	if rec := h.do(t, http.MethodDelete, "/api/v1/mcp/policies/"+policy.ID.String(), nil, true); rec.Code != 204 {
		t.Fatal("delete policy")
	}

	if rec := h.do(t, http.MethodGet, "/api/v1/mcp/audit?connectionId=bad", nil, true); rec.Code != 400 {
		t.Fatal("bad audit filter")
	}
	page := decode[mcpAuditPageResponse](t, h.do(t, http.MethodGet, "/api/v1/mcp/audit?connectionId="+connection.ID.String()+"&limit=10", nil, true))
	if page.Total != 0 {
		t.Fatal("unexpected audit")
	}
	if rec := h.do(t, http.MethodDelete, "/api/v1/mcp/connections/"+connection.ID.String(), nil, true); rec.Code != 204 {
		t.Fatal("delete connection")
	}
}

func TestMCPProtocolProbeClassifications(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantEra    string
		wantStatus string
		wantDetail string
	}{
		{
			name: "modern July", status: http.StatusOK, wantEra: "modern_2026_07", wantStatus: "compatible", wantDetail: "discovery_valid",
			body: `{"jsonrpc":"2.0","id":"dwv-probe","result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"Example MCP","version":"2"}},"ttlMs":3600000,"cacheScope":"public"}}`,
		},
		{name: "legacy method not found", status: http.StatusOK, body: `{"jsonrpc":"2.0","id":"dwv-probe","error":{"code":-32601,"message":"Method not found"}}`, wantEra: "legacy_session_likely", wantStatus: "incompatible", wantDetail: "method_not_found"},
		{name: "authorization required", status: http.StatusUnauthorized, body: `unauthorized`, wantEra: "unknown", wantStatus: "auth_required", wantDetail: "authorization_status"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Mcp-Method") != "server/discover" || r.Header.Get("MCP-Protocol-Version") != mcp.ProtocolVersion {
					t.Errorf("missing probe headers: %v", r.Header)
				}
				requestBody, _ := io.ReadAll(r.Body)
				if !bytes.Contains(requestBody, []byte(`"id":"dwv-probe"`)) {
					t.Errorf("wrong probe request: %s", requestBody)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer upstream.Close()
			h := newHarness(t)
			h.server.deps.MCPClient = upstream.Client()
			connection := createMCPConnection(t, h, upstream.URL)
			rec := h.do(t, http.MethodPost, "/api/v1/mcp/connections/"+connection.ID.String()+"/probe", nil, true)
			if rec.Code != http.StatusOK {
				t.Fatalf("probe %d: %s", rec.Code, rec.Body)
			}
			got := decode[mcpConnectionDTO](t, rec)
			if got.ProtocolEra != test.wantEra || got.ProbeStatus != test.wantStatus || got.ProbeDetail == nil || *got.ProbeDetail != test.wantDetail || got.ProbeCheckedAt == nil {
				t.Fatalf("classification: %+v", got)
			}
			if test.wantStatus == "compatible" && (got.ServerName == nil || *got.ServerName != "Example MCP" || len(got.SupportedVersions) != 1) {
				t.Fatalf("modern metadata: %+v", got)
			}
			if test.wantStatus == "compatible" {
				got.Name = "Edited after probe"
				update := h.do(t, http.MethodPut, "/api/v1/mcp/connections/"+connection.ID.String(), upsertMCPConnectionRequest{
					Slug: got.Slug, Name: got.Name, Description: got.Description, UpstreamURL: got.UpstreamURL,
					AuthMode: got.AuthMode, AuditMode: got.AuditMode, UpstreamProtocolMode: "legacy_session", LegacyProtocolVersion: "2025-03-26", Enabled: boolPtr(got.Enabled),
				}, true)
				if update.Code != http.StatusOK {
					t.Fatalf("edit after probe %d: %s", update.Code, update.Body)
				}
				edited := decode[mcpConnectionDTO](t, update)
				if edited.Name != got.Name || edited.UpstreamProtocolMode != "legacy_session" || edited.LegacyProtocolVersion != "2025-03-26" || edited.ProbeStatus != got.ProbeStatus ||
					edited.ProbeCheckedAt == nil || edited.ServerName == nil ||
					len(edited.SupportedVersions) != len(got.SupportedVersions) {
					t.Fatalf("edit response lost probe metadata: %+v", edited)
				}
			}
		})
	}
}

func TestMCPProtocolProbeUnavailable(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	h := newHarness(t)
	h.server.deps.MCPClient = upstream.Client()
	connection := createMCPConnection(t, h, upstream.URL)
	upstream.Close()
	rec := h.do(t, http.MethodPost, "/api/v1/mcp/connections/"+connection.ID.String()+"/probe", nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("probe %d: %s", rec.Code, rec.Body)
	}
	got := decode[mcpConnectionDTO](t, rec)
	if got.ProtocolEra != "unknown" || got.ProbeStatus != "unreachable" || got.ProbeDetail == nil || *got.ProbeDetail != "network_failure" {
		t.Fatalf("unavailable classification: %+v", got)
	}
	if rec := h.do(t, http.MethodPost, "/api/v1/mcp/connections/"+uuid.NewString()+"/probe", nil, true); rec.Code != http.StatusNotFound {
		t.Fatalf("missing probe %d", rec.Code)
	}
}

func TestMCPProtocolProbeOAuthAuthorizationUnavailable(t *testing.T) {
	h := newHarness(t)
	connection := createMCPConnection(t, h, "https://example.com/mcp")
	rec := h.do(t, http.MethodPut, "/api/v1/mcp/connections/"+connection.ID.String(), upsertMCPConnectionRequest{
		Slug: connection.Slug, Name: connection.Name, UpstreamURL: connection.UpstreamURL,
		AuthMode: "oauth", AuditMode: connection.AuditMode, UpstreamProtocolMode: connection.UpstreamProtocolMode,
		LegacyProtocolVersion: connection.LegacyProtocolVersion, Enabled: boolPtr(true),
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("set OAuth mode %d: %s", rec.Code, rec.Body)
	}

	rec = h.do(t, http.MethodPost, "/api/v1/mcp/connections/"+connection.ID.String()+"/probe", nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("probe %d: %s", rec.Code, rec.Body)
	}
	got := decode[mcpConnectionDTO](t, rec)
	if got.ProtocolEra != "unknown" || got.ProbeStatus != "auth_required" || got.ProbeDetail == nil || *got.ProbeDetail != "authorization_unavailable" || got.ProbeCheckedAt == nil {
		t.Fatalf("OAuth-unavailable classification: %+v", got)
	}
	stored, err := h.ms.GetMCPConnectionByID(t.Context(), h.userID, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil || stored.ProbeStatus != "auth_required" {
		t.Fatalf("probe result was not persisted: %+v", stored)
	}
}

func TestMCPProtocolProbeSSEModern(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		_, _ = w.Write([]byte(": keepalive\n\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n" +
			"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"dwv-probe\",\"result\":{\"resultType\":\"complete\",\"supportedVersions\":[\"2026-07-28\"],\"capabilities\":{\"tools\":{}},\"_meta\":{\"io.modelcontextprotocol/serverInfo\":{\"name\":\"Streaming MCP\",\"version\":\"1\"}},\"ttlMs\":1000,\"cacheScope\":\"public\"}}\n\n"))
	}))
	defer upstream.Close()
	h := newHarness(t)
	h.server.deps.MCPClient = upstream.Client()
	connection := createMCPConnection(t, h, upstream.URL)
	rec := h.do(t, http.MethodPost, "/api/v1/mcp/connections/"+connection.ID.String()+"/probe", nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("probe %d: %s", rec.Code, rec.Body)
	}
	got := decode[mcpConnectionDTO](t, rec)
	if got.ProtocolEra != "modern_2026_07" || got.ProbeStatus != "compatible" || got.ServerName == nil || *got.ServerName != "Streaming MCP" {
		t.Fatalf("SSE probe classification: %+v", got)
	}
}

func TestMCPProtocolProbeRedirectDoesNotFollowOrLeakAuth(t *testing.T) {
	redirectCalls := 0
	redirectTarget := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		redirectCalls++
		if r.Header.Get("X-Upstream") != "" {
			t.Error("probe credential leaked to redirect target")
		}
	}))
	defer redirectTarget.Close()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Upstream") != "Bearer static-secret" {
			t.Fatalf("static auth missing at configured endpoint: %q", r.Header.Get("X-Upstream"))
		}
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer upstream.Close()
	h := newHarness(t)
	h.server.deps.MCPClient = upstream.Client()
	connection := createMCPConnection(t, h, upstream.URL)
	secret, err := h.cipher.EncryptString("static-secret")
	if err != nil {
		t.Fatal(err)
	}
	headerName, prefix := "X-Upstream", "Bearer "
	credential := &store.APIKey{UserID: h.userID, Name: "probe auth", FieldsCipher: secret, Kind: "header_api_key", HeaderName: &headerName, Prefix: &prefix}
	if err := h.ms.InsertAPIKey(t.Context(), credential); err != nil {
		t.Fatal(err)
	}
	if err := h.ms.InsertMCPHeaderBinding(t.Context(), &store.MCPHeaderBinding{UserID: h.userID, ConnectionID: connection.ID, CredentialID: credential.ID}); err != nil {
		t.Fatal(err)
	}
	rec := h.do(t, http.MethodPost, "/api/v1/mcp/connections/"+connection.ID.String()+"/probe", nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("probe %d: %s", rec.Code, rec.Body)
	}
	got := decode[mcpConnectionDTO](t, rec)
	if redirectCalls != 0 || got.ProtocolEra != "unknown" || got.ProbeDetail == nil || *got.ProbeDetail != "redirect" {
		t.Fatalf("redirect classification/calls: %d %+v", redirectCalls, got)
	}
}

func TestMCPProtocolProbeOversizedResponse(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bytes.Repeat([]byte{'x'}, maxRequestBody+1))
	}))
	defer upstream.Close()
	h := newHarness(t)
	h.server.deps.MCPClient = upstream.Client()
	connection := createMCPConnection(t, h, upstream.URL)
	rec := h.do(t, http.MethodPost, "/api/v1/mcp/connections/"+connection.ID.String()+"/probe", nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("probe %d: %s", rec.Code, rec.Body)
	}
	got := decode[mcpConnectionDTO](t, rec)
	if got.ProbeStatus != "unreachable" || got.ProbeDetail == nil || *got.ProbeDetail != "response_too_large" {
		t.Fatalf("oversized classification: %+v", got)
	}
}

func TestMCPProtocolProbeDisabledConnection(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"dwv-probe","result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":1000,"cacheScope":"public"}}`))
	}))
	defer upstream.Close()
	h := newHarness(t)
	h.server.deps.MCPClient = upstream.Client()
	connection := createMCPConnection(t, h, upstream.URL)
	disabled := false
	rec := h.do(t, http.MethodPut, "/api/v1/mcp/connections/"+connection.ID.String(), upsertMCPConnectionRequest{
		Slug: connection.Slug, Name: connection.Name, UpstreamURL: connection.UpstreamURL,
		AuthMode: connection.AuthMode, AuditMode: connection.AuditMode,
		UpstreamProtocolMode: connection.UpstreamProtocolMode, LegacyProtocolVersion: connection.LegacyProtocolVersion, Enabled: &disabled,
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable %d: %s", rec.Code, rec.Body)
	}
	rec = h.do(t, http.MethodPost, "/api/v1/mcp/connections/"+connection.ID.String()+"/probe", nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("disabled admin probe failed: %d %s", rec.Code, rec.Body)
	}
	got := decode[mcpConnectionDTO](t, rec)
	if upstreamCalls != 1 || got.ProbeStatus != "compatible" || got.Enabled {
		t.Fatalf("disabled admin probe result/calls: %d %+v", upstreamCalls, got)
	}
}

func TestMCPProxyJSONAndPolicy(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Api-Key") != "" {
			t.Error("downstream auth leaked")
		}
		if r.Header.Get("Mcp-Method") != "tools/call" {
			t.Error("method header missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","content":[]}}`))
	}))
	defer upstream.Close()
	h := newHarness(t)
	// Test TLS uses a local CA; the production client remains SSRF-hardened and system-trusted.
	h.server.deps.MCPClient = upstream.Client()
	connection := createMCPConnection(t, h, upstream.URL)
	accessKey := firstAccessKey(t, h)
	grant := &store.MCPConnectionGrant{UserID: h.userID, ConnectionID: connection.ID, AccessKeyID: accessKey.ID}
	if err := h.ms.InsertMCPConnectionGrant(t.Context(), grant); err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed","arguments":{"password":"hide"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}}`)
	rec := mcpRequest(t, h, body, "tools/call", "allowed")
	if rec.Code != 200 {
		t.Fatalf("proxy %d %s", rec.Code, rec.Body)
	}
	page := decode[mcpAuditPageResponse](t, h.do(t, http.MethodGet, "/api/v1/mcp/audit?connectionId="+connection.ID.String(), nil, true))
	var requestPayload string
	for _, item := range page.Items {
		if item.Direction == "client_to_server" && item.PayloadRedacted != nil {
			requestPayload = *item.PayloadRedacted
		}
	}
	if page.Total != 2 || !bytes.Contains([]byte(requestPayload), []byte(`"password":"***"`)) {
		t.Fatalf("audit %#v", page)
	}

	policy := &store.MCPToolPolicy{UserID: h.userID, ConnectionID: connection.ID, Method: "tools/call", ToolName: "allowed", Allow: true}
	if err := h.ms.UpsertMCPToolPolicy(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	rec = mcpRequest(t, h, bytes.Replace(body, []byte(`"allowed"`), []byte(`"blocked"`), 1), "tools/call", "blocked")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("denied %d %s", rec.Code, rec.Body)
	}
	rec = mcpRequest(t, h, []byte(`{"bad":true}`), "tools/call", "allowed")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed %d %s", rec.Code, rec.Body)
	}
}

func TestMCPProxySSE(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(": keepalive\n\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\"}}\n\n"))
	}))
	defer upstream.Close()
	h := newHarness(t)
	h.server.deps.MCPClient = upstream.Client()
	connection := createMCPConnection(t, h, upstream.URL)
	key := firstAccessKey(t, h)
	if err := h.ms.InsertMCPConnectionGrant(t.Context(), &store.MCPConnectionGrant{UserID: h.userID, ConnectionID: connection.ID, AccessKeyID: key.ID}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}}`)
	rec := mcpRequest(t, h, body, "subscriptions/listen", "")
	if rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte("notifications/progress")) {
		t.Fatalf("SSE %d %s", rec.Code, rec.Body)
	}
	page := decode[mcpAuditPageResponse](t, h.do(t, http.MethodGet, "/api/v1/mcp/audit?connectionId="+connection.ID.String(), nil, true))
	if page.Total != 3 {
		t.Fatalf("SSE audit total %d", page.Total)
	}
}

func TestMCPProxyDiscoveryIsGatewayOwned(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls++
	}))
	defer upstream.Close()
	h := newHarness(t)
	h.server.deps.MCPClient = upstream.Client()
	h.server.deps.ServiceVersion = "test-version"
	connection := createMCPConnection(t, h, upstream.URL)
	key := firstAccessKey(t, h)
	if err := h.ms.InsertMCPConnectionGrant(t.Context(), &store.MCPConnectionGrant{UserID: h.userID, ConnectionID: connection.ID, AccessKeyID: key.ID}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"jsonrpc":"2.0","id":"discover-1","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}}`)
	rec := mcpRequest(t, h, body, "server/discover", "")
	if rec.Code != http.StatusOK || upstreamCalls != 0 {
		t.Fatalf("discovery status %d, upstream calls %d: %s", rec.Code, upstreamCalls, rec.Body)
	}
	if got := rec.Header().Get("Cache-Control"); got != "private, max-age=3600" {
		t.Fatalf("unexpected discovery cache header %q", got)
	}
	var envelope struct {
		ID     string `json:"id"`
		Result struct {
			ResultType        string                     `json:"resultType"`
			SupportedVersions []string                   `json:"supportedVersions"`
			Capabilities      map[string]json.RawMessage `json:"capabilities"`
			Meta              map[string]json.RawMessage `json:"_meta"`
			TTLMS             int64                      `json:"ttlMs"`
			CacheScope        string                     `json:"cacheScope"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ID != "discover-1" || envelope.Result.ResultType != "complete" || envelope.Result.CacheScope != "private" || envelope.Result.TTLMS != 3_600_000 || len(envelope.Result.SupportedVersions) != 1 || envelope.Result.SupportedVersions[0] != mcp.ProtocolVersion {
		t.Fatalf("unexpected discovery: %+v", envelope)
	}
	if _, ok := envelope.Result.Capabilities["tools"]; !ok || len(envelope.Result.Capabilities) != 1 {
		t.Fatalf("unexpected capabilities: %s", rec.Body)
	}
	if !bytes.Contains(envelope.Result.Meta["io.modelcontextprotocol/serverInfo"], []byte(`"name":"DonkeyWork Vault"`)) || !bytes.Contains(envelope.Result.Meta["io.modelcontextprotocol/serverInfo"], []byte(`"version":"test-version"`)) {
		t.Fatalf("unexpected identity: %s", rec.Body)
	}
	page := decode[mcpAuditPageResponse](t, h.do(t, http.MethodGet, "/api/v1/mcp/audit?connectionId="+connection.ID.String(), nil, true))
	if page.Total != 2 {
		t.Fatalf("discovery audit total %d", page.Total)
	}
}

func TestMCPProxyFiltersToolsAndEnforcesParameterHeaders(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.Header().Set("Content-Type", "application/json")
		switch r.Header.Get("Mcp-Method") {
		case "tools/list":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","tools":[` +
				`{"name":"allowed","inputSchema":{"type":"object","required":["region"],"properties":{"region":{"type":"string","x-mcp-header":"Region"}}}},` +
				`{"name":"blocked","inputSchema":{"type":"object"}},` +
				`{"name":"invalid","inputSchema":{"type":"object","properties":{"value":{"type":"number","x-mcp-header":"Value"}}}}` +
				`],"ttlMs":300000,"cacheScope":"public"}}`))
		case "tools/call":
			if r.Header.Get("Mcp-Param-Region") != "us-east-1" {
				t.Errorf("missing upstream parameter header: %q", r.Header.Get("Mcp-Param-Region"))
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[]}}`))
		default:
			t.Errorf("unexpected method %q", r.Header.Get("Mcp-Method"))
		}
	}))
	defer upstream.Close()
	h := newHarness(t)
	h.server.deps.MCPClient = upstream.Client()
	connection := createMCPConnection(t, h, upstream.URL)
	key := firstAccessKey(t, h)
	if err := h.ms.InsertMCPConnectionGrant(t.Context(), &store.MCPConnectionGrant{UserID: h.userID, ConnectionID: connection.ID, AccessKeyID: key.ID}); err != nil {
		t.Fatal(err)
	}
	if err := h.ms.UpsertMCPToolPolicy(t.Context(), &store.MCPToolPolicy{UserID: h.userID, ConnectionID: connection.ID, Method: "tools/call", ToolName: "allowed", Allow: true}); err != nil {
		t.Fatal(err)
	}

	listBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}}`)
	rec := mcpRequest(t, h, listBody, "tools/list", "")
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"name":"allowed"`)) || bytes.Contains(rec.Body.Bytes(), []byte(`"name":"blocked"`)) || bytes.Contains(rec.Body.Bytes(), []byte(`"name":"invalid"`)) || !bytes.Contains(rec.Body.Bytes(), []byte(`"cacheScope":"private"`)) {
		t.Fatalf("filtered list %d: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Cache-Control"); got != "private" {
		t.Fatalf("unexpected tools cache header %q", got)
	}
	metadata, err := h.ms.ListMCPToolParameterHeaders(t.Context(), h.userID, connection.ID, "allowed")
	if err != nil || len(metadata) != 1 || metadata[0].HeaderName != "Region" || !metadata[0].Required {
		t.Fatalf("stored metadata: %+v, %v", metadata, err)
	}

	callBody := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"allowed","arguments":{"region":"us-east-1"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}}`)
	beforeCall := upstreamCalls
	for name, value := range map[string]string{"missing": "", "mismatch": "us-west-2"} {
		t.Run(name, func(t *testing.T) {
			rec := mcpRequestWithHeaders(t, h, callBody, "tools/call", "allowed", map[string]string{"Mcp-Param-Region": value})
			if rec.Code != http.StatusBadRequest || !bytes.Contains(rec.Body.Bytes(), []byte(`"code":-32020`)) {
				t.Fatalf("header rejection %d: %s", rec.Code, rec.Body)
			}
		})
	}
	if upstreamCalls != beforeCall {
		t.Fatalf("invalid calls reached upstream: before %d after %d", beforeCall, upstreamCalls)
	}
	rec = mcpRequestWithHeaders(t, h, callBody, "tools/call", "allowed", map[string]string{"Mcp-Param-Region": "us-east-1"})
	if rec.Code != http.StatusOK || upstreamCalls != beforeCall+1 {
		t.Fatalf("allowed call %d upstream %d: %s", rec.Code, upstreamCalls, rec.Body)
	}
}

func TestMCPProxyFiltersSSEToolsList(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(": keepalive\n\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n" +
			"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\",\"tools\":[{\"name\":\"allowed\",\"inputSchema\":{\"type\":\"object\"}},{\"name\":\"blocked\",\"inputSchema\":{\"type\":\"object\"}}],\"ttlMs\":1000,\"cacheScope\":\"public\"}}\n\n"))
	}))
	defer upstream.Close()
	h := newHarness(t)
	h.server.deps.MCPClient = upstream.Client()
	connection := createMCPConnection(t, h, upstream.URL)
	key := firstAccessKey(t, h)
	if err := h.ms.InsertMCPConnectionGrant(t.Context(), &store.MCPConnectionGrant{UserID: h.userID, ConnectionID: connection.ID, AccessKeyID: key.ID}); err != nil {
		t.Fatal(err)
	}
	if err := h.ms.UpsertMCPToolPolicy(t.Context(), &store.MCPToolPolicy{UserID: h.userID, ConnectionID: connection.ID, Method: "tools/call", ToolName: "allowed", Allow: true}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}}`)
	rec := mcpRequest(t, h, body, "tools/list", "")
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"name":"allowed"`)) || bytes.Contains(rec.Body.Bytes(), []byte(`"name":"blocked"`)) || !bytes.Contains(rec.Body.Bytes(), []byte(`"cacheScope":"private"`)) {
		t.Fatalf("filtered SSE %d: %s", rec.Code, rec.Body)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("event: message")) || !bytes.Contains(rec.Body.Bytes(), []byte("notifications/progress")) || rec.Header().Get("Cache-Control") != "private" {
		t.Fatalf("SSE metadata lost: headers=%v body=%s", rec.Header(), rec.Body)
	}
	page := decode[mcpAuditPageResponse](t, h.do(t, http.MethodGet, "/api/v1/mcp/audit?connectionId="+connection.ID.String(), nil, true))
	if page.Total != 3 {
		t.Fatalf("SSE audit total %d", page.Total)
	}
}

func TestMCPResponseTransformationPaginationAndErrors(t *testing.T) {
	h := newHarness(t)
	connection := createMCPConnection(t, h, "https://example.com/mcp")
	resolved := &service.MCPResolvedConnection{Connection: store.MCPConnection{ID: connection.ID, UserID: h.userID}, Policy: mcp.Policy{Tools: mcp.AllowRule{Default: mcp.DefaultAllow}}}
	ctx := contracts.WithCaller(context.Background(), contracts.Caller{UserID: h.userID})
	if got, err := h.server.transformMCPResponse(ctx, mcp.ClientMessage{Audit: mcp.AuditFields{Method: "resources/list"}}, resolved, []byte(`{"unchanged":true}`)); err != nil || string(got) != `{"unchanged":true}` {
		t.Fatalf("unrelated response: %s %v", got, err)
	}
	if _, err := h.server.transformMCPResponse(ctx, mcp.ClientMessage{Audit: mcp.AuditFields{Method: "tools/list"}}, resolved, []byte(`{}`)); err == nil {
		t.Fatal("expected invalid tools response")
	}
	paginated := []byte(`{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","tools":[{"name":"page","inputSchema":{"type":"object","properties":{"site":{"type":"string","x-mcp-header":"Site"}}}}],"nextCursor":"next","ttlMs":1000,"cacheScope":"public"}}`)
	if _, err := h.server.transformMCPResponse(ctx, mcp.ClientMessage{Audit: mcp.AuditFields{Method: "tools/list"}}, resolved, paginated); err != nil {
		t.Fatal(err)
	}
	if rows, err := h.ms.ListMCPToolParameterHeaders(ctx, h.userID, connection.ID, "page"); err != nil || len(rows) != 1 {
		t.Fatalf("paginated metadata: %+v %v", rows, err)
	}
}

func TestMCPToolsListSSERejectsInvalidStreams(t *testing.T) {
	for _, test := range []struct {
		name, stream string
	}{
		{name: "incomplete", stream: `data: {"jsonrpc":"2.0","id":1,"result":{}}`},
		{name: "malformed", stream: "data: {bad}\n\n"},
		{name: "no final", stream: ": keepalive\n\n"},
		{name: "multiple final", stream: "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\",\"tools\":[],\"ttlMs\":1,\"cacheScope\":\"public\"}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\",\"tools\":[],\"ttlMs\":1,\"cacheScope\":\"public\"}}\n\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte(test.stream))
			}))
			defer upstream.Close()
			h := newHarness(t)
			h.server.deps.MCPClient = upstream.Client()
			connection := createMCPConnection(t, h, upstream.URL)
			key := firstAccessKey(t, h)
			if err := h.ms.InsertMCPConnectionGrant(t.Context(), &store.MCPConnectionGrant{UserID: h.userID, ConnectionID: connection.ID, AccessKeyID: key.ID}); err != nil {
				t.Fatal(err)
			}
			body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}}`)
			rec := mcpRequest(t, h, body, "tools/list", "")
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("invalid stream %d: %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestMCPProxyUpstreamFailures(t *testing.T) {
	for _, test := range []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "malformed json", contentType: "application/json", body: `{bad}`},
		{name: "wrong result shape", contentType: "application/json", body: `{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete"}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				_, _ = w.Write([]byte(test.body))
			}))
			defer upstream.Close()
			h := newHarness(t)
			h.server.deps.MCPClient = upstream.Client()
			connection := createMCPConnection(t, h, upstream.URL)
			key := firstAccessKey(t, h)
			if err := h.ms.InsertMCPConnectionGrant(t.Context(), &store.MCPConnectionGrant{UserID: h.userID, ConnectionID: connection.ID, AccessKeyID: key.ID}); err != nil {
				t.Fatal(err)
			}
			body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}}`)
			rec := mcpRequest(t, h, body, "tools/list", "")
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("upstream failure %d: %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestMCPOAuthHandlers(t *testing.T) {
	h := newHarness(t)
	connection := createMCPConnection(t, h, "https://example.com/mcp")
	path := "/api/v1/mcp/connections/" + connection.ID.String() + "/oauth"
	if rec := h.do(t, http.MethodPut, path, configureMCPOAuthRequest{}, true); rec.Code != 400 {
		t.Fatalf("invalid config %d", rec.Code)
	}
	if rec := h.do(t, http.MethodPut, path, configureMCPOAuthRequest{ClientID: "client", Scopes: []string{"read"}}, true); rec.Code != 204 {
		t.Fatalf("config %d %s", rec.Code, rec.Body)
	}
	if rec := h.do(t, http.MethodGet, path+"/connect", nil, true); rec.Code != 400 {
		t.Fatalf("unreachable discovery %d", rec.Code)
	}
	if rec := h.do(t, http.MethodDelete, path, nil, true); rec.Code != 204 {
		t.Fatalf("delete OAuth %d", rec.Code)
	}
	if rec := h.do(t, http.MethodDelete, path, nil, true); rec.Code != 404 {
		t.Fatalf("delete OAuth twice %d", rec.Code)
	}
	for _, query := range []string{"?error=denied", "?code=x&state=missing"} {
		req := httptest.NewRequest(http.MethodGet, "/api/mcp/oauth/callback"+query, nil)
		rec := httptest.NewRecorder()
		h.h.ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Fatalf("callback %s: %d", query, rec.Code)
		}
	}
}

func TestMCPHelpers(t *testing.T) {
	if got := messageIDValue(mcp.ID{Kind: mcp.IDString, Value: "x"}); got != "x" {
		t.Fatalf("string id %v", got)
	}
	if got := messageIDValue(mcp.ID{Kind: mcp.IDNumber, Value: "7"}); got != json.Number("7") {
		t.Fatalf("number id %v", got)
	}
	if got := messageIDValue(mcp.ID{}); got != nil {
		t.Fatalf("nil id %v", got)
	}
	if decodeDigest("") != nil || string(decodeDigest("digest")) != "digest" {
		t.Fatal("digest")
	}
	for _, tc := range []struct {
		raw                      string
		fallback, min, max, want int
	}{{"bad", 5, 1, 10, 5}, {"0", 5, 1, 10, 1}, {"20", 5, 1, 10, 10}, {"7", 5, 1, 10, 7}} {
		req := httptest.NewRequest(http.MethodGet, "/?n="+tc.raw, nil)
		if got := queryInt(req, "n", tc.fallback, tc.min, tc.max); got != tc.want {
			t.Fatalf("query %s got %d", tc.raw, got)
		}
	}
	if payload, _, truncated := redactMCPPayload(bytes.Repeat([]byte("x"), maxMCPAuditPayload+1)); payload != nil || !truncated {
		t.Fatal("truncation")
	}
	h := newHarness(t)
	if !h.server.validMCPOrigin("") || !h.server.validMCPOrigin("https://vault.example") || h.server.validMCPOrigin("https://evil.example") || h.server.validMCPOrigin("not a URL") {
		t.Fatal("origin validation")
	}
	validHeaders := http.Header{"Content-Type": {"application/json; charset=utf-8"}, "Accept": {"application/json, text/event-stream"}}
	if !validMCPContentHeaders(validHeaders) || validMCPContentHeaders(http.Header{}) {
		t.Fatal("content header validation")
	}
	buffer := bytes.NewBufferString("data: one\r\n\r\ndata: two\n\n")
	if event, ok := takeSSEEvent(buffer); !ok || !bytes.Contains(event, []byte("one")) {
		t.Fatal("CRLF SSE")
	}
	if event, ok := takeSSEEvent(buffer); !ok || !bytes.Contains(event, []byte("two")) {
		t.Fatal("LF SSE")
	}
	if _, ok := takeSSEEvent(buffer); ok {
		t.Fatal("unexpected event")
	}
}

func TestMCPProxyRejectsOriginAndContentHeaders(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/proxy/example", nil)
	req.Header.Set("X-Api-Key", h.secret)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("origin %d", rec.Code)
	}
}

func firstAccessKey(t *testing.T, h *harness) store.AccessKey {
	t.Helper()
	rows, err := h.ms.ListAccessKeys(t.Context(), h.userID)
	if err != nil || len(rows) == 0 {
		t.Fatal("missing access key")
	}
	return rows[0]
}

func mcpRequest(t *testing.T, h *harness, body []byte, method, name string) *httptest.ResponseRecorder {
	return mcpRequestWithHeaders(t, h, body, method, name, nil)
}

func mcpRequestWithHeaders(t *testing.T, h *harness, body []byte, method, name string, extra map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/proxy/example", bytes.NewReader(body))
	req.Header.Set("X-Api-Key", h.secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", method)
	if name != "" {
		req.Header.Set("Mcp-Name", name)
	}
	for key, value := range extra {
		if value != "" {
			req.Header.Set(key, value)
		}
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func boolPtr(value bool) *bool { return &value }
