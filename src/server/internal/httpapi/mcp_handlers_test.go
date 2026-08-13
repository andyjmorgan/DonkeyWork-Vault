package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"donkeywork.dev/vault-server/internal/mcp"
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
	if rows := decode[[]mcpConnectionDTO](t, h.do(t, http.MethodGet, "/api/v1/mcp/connections", nil, true)); len(rows) != 1 {
		t.Fatal("list")
	}
	connection.Name = "Updated"
	rec := h.do(t, http.MethodPut, "/api/v1/mcp/connections/"+connection.ID.String(), upsertMCPConnectionRequest{Slug: connection.Slug, Name: connection.Name, UpstreamURL: connection.UpstreamURL, AuthMode: "headers", AuditMode: "metadata", Enabled: boolPtr(true)}, true)
	if rec.Code != http.StatusOK || decode[mcpConnectionDTO](t, rec).Name != "Updated" {
		t.Fatal("update")
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
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}}`)
	rec := mcpRequest(t, h, body, "tools/list", "")
	if rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte("notifications/progress")) {
		t.Fatalf("SSE %d %s", rec.Code, rec.Body)
	}
	page := decode[mcpAuditPageResponse](t, h.do(t, http.MethodGet, "/api/v1/mcp/audit?connectionId="+connection.ID.String(), nil, true))
	if page.Total != 3 {
		t.Fatalf("SSE audit total %d", page.Total)
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
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func boolPtr(value bool) *bool { return &value }
