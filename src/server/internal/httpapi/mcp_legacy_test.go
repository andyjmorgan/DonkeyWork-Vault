package httpapi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/store"
)

func createLegacyMCPConnection(t *testing.T, h *harness, upstream string) mcpConnectionDTO {
	t.Helper()
	enabled := true
	rec := h.do(t, http.MethodPost, "/api/v1/mcp/connections", upsertMCPConnectionRequest{
		Slug: "legacy", Name: "Legacy", UpstreamURL: upstream, AuthMode: "none", AuditMode: "redacted",
		UpstreamProtocolMode: "legacy_session", LegacyProtocolVersion: "2025-06-18", Enabled: &enabled,
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("create legacy MCP %d: %s", rec.Code, rec.Body)
	}
	return decode[mcpConnectionDTO](t, rec)
}

func TestMCPProxyLegacySessionJSON(t *testing.T) {
	initializes, initialized, calls := 0, 0, 0
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case bytes.Contains(body, []byte(`"method":"initialize"`)):
			initializes++
			w.Header().Set("MCP-Session-Id", "legacy-session")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"dwv-legacy-initialize","result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"Legacy","version":"1"}}}`))
		case bytes.Contains(body, []byte(`"method":"notifications/initialized"`)):
			initialized++
			w.WriteHeader(http.StatusAccepted)
		default:
			calls++
			if r.Header.Get("MCP-Protocol-Version") != "2025-06-18" || r.Header.Get("MCP-Session-Id") != "legacy-session" || bytes.Contains(body, []byte("2026-07-28")) {
				t.Errorf("legacy translation headers=%v body=%s", r.Header, body)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"legacy_tool","inputSchema":{"type":"object"}}]}}`))
		}
	}))
	defer upstream.Close()
	h := newHarness(t)
	h.server.deps.MCPClient = upstream.Client()
	connection := createLegacyMCPConnection(t, h, upstream.URL)
	key := firstAccessKey(t, h)
	if err := h.ms.InsertMCPConnectionGrant(t.Context(), &store.MCPConnectionGrant{UserID: h.userID, ConnectionID: connection.ID, AccessKeyID: key.ID}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}}`)
	for range 2 {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/proxy/legacy", bytes.NewReader(body))
		req.Header.Set("X-Api-Key", h.secret)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2026-07-28")
		req.Header.Set("Mcp-Method", "tools/list")
		rec := httptest.NewRecorder()
		h.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"name":"legacy_tool"`)) || !bytes.Contains(rec.Body.Bytes(), []byte(`"resultType":"complete"`)) || !bytes.Contains(rec.Body.Bytes(), []byte(`"cacheScope":"private"`)) {
			t.Fatalf("legacy proxy %d: %s", rec.Code, rec.Body)
		}
	}
	if initializes != 1 || initialized != 1 || calls != 2 {
		t.Fatalf("initialize=%d initialized=%d calls=%d", initializes, initialized, calls)
	}
	page := decode[mcpAuditPageResponse](t, h.do(t, http.MethodGet, "/api/v1/mcp/audit?connectionId="+connection.ID.String(), nil, true))
	if page.Total != 7 {
		t.Fatalf("legacy lifecycle audit total %d", page.Total)
	}
	methods := map[string]bool{}
	for _, item := range page.Items {
		if item.Method != nil {
			methods[*item.Method] = true
		}
	}
	if !methods["initialize"] || !methods["notifications/initialized"] || !methods["tools/list"] {
		t.Fatalf("missing lifecycle audit methods: %+v", methods)
	}
}

func TestMCPProxyLegacyUpgradeFailureIsAudited(t *testing.T) {
	const rejectedBody = `{"jsonrpc":"2.0","id":1,"result":{"tools":"invalid"}}`
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case bytes.Contains(body, []byte(`"method":"initialize"`)):
			w.Header().Set("MCP-Session-Id", "legacy-session")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"dwv-legacy-initialize","result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"Legacy","version":"1"}}}`))
		case bytes.Contains(body, []byte(`"method":"notifications/initialized"`)):
			w.WriteHeader(http.StatusAccepted)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(rejectedBody))
		}
	}))
	defer upstream.Close()
	h := newHarness(t)
	h.server.deps.MCPClient = upstream.Client()
	connection := createLegacyMCPConnection(t, h, upstream.URL)
	key := firstAccessKey(t, h)
	if err := h.ms.InsertMCPConnectionGrant(t.Context(), &store.MCPConnectionGrant{UserID: h.userID, ConnectionID: connection.ID, AccessKeyID: key.ID}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/proxy/legacy", bytes.NewReader(body))
	for name, value := range map[string]string{"X-Api-Key": h.secret, "Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"} {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("legacy rejection %d: %s", rec.Code, rec.Body)
	}
	rows, _, err := h.ms.QueryMCPAudit(t.Context(), store.MCPAuditFilter{UserID: h.userID, Limit: 10, ConnectionID: &connection.ID})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Direction == "server_to_client" && row.PolicyDecision == "upstream_rejected" {
			if row.MessageKind != "malformed" || row.PayloadBytes != int64(len(rejectedBody)) || row.PayloadRedacted == nil {
				t.Fatalf("legacy rejected audit: %+v", row)
			}
			return
		}
	}
	t.Fatalf("missing legacy rejection audit: %+v", rows)
}

func TestLegacyAdapterPoolLifecycle(t *testing.T) {
	pool := newLegacyAdapterPool()
	client := &http.Client{}
	connection := store.MCPConnection{ID: uuid.New(), UpstreamURL: "https://example.com/mcp", LegacyProtocolVersion: "2025-06-18"}
	first, err := pool.adapter(connection, client, "test")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := pool.adapter(connection, client, "test")
	if first != second {
		t.Fatal("adapter was not reused")
	}
	connection.LegacyProtocolVersion = "2025-11-25"
	replaced, _ := pool.adapter(connection, client, "test")
	if replaced == first {
		t.Fatal("changed config reused adapter")
	}
	if expired := pool.expireIdle(time.Now().Add(time.Hour)); expired != 0 {
		t.Fatalf("expired uninitialized adapters: %d", expired)
	}
	if err := pool.remove(t.Context(), connection.ID, nil); err != nil || len(pool.entries) != 0 {
		t.Fatalf("remove: %v entries=%d", err, len(pool.entries))
	}
}

func TestMCPProxyLegacySessionSSE(t *testing.T) {
	legacyStream := "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n" +
		"event: result\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"value\":\"legacy\"}}\n\n"
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case bytes.Contains(body, []byte(`"method":"initialize"`)):
			w.Header().Set("MCP-Session-Id", "legacy-session")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"dwv-legacy-initialize","result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"Legacy","version":"1"}}}`))
		case bytes.Contains(body, []byte(`"method":"notifications/initialized"`)):
			w.WriteHeader(http.StatusAccepted)
		default:
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(legacyStream))
		}
	}))
	defer upstream.Close()
	h := newHarness(t)
	h.server.deps.MCPClient = upstream.Client()
	connection := createLegacyMCPConnection(t, h, upstream.URL)
	key := firstAccessKey(t, h)
	if err := h.ms.InsertMCPConnectionGrant(t.Context(), &store.MCPConnectionGrant{UserID: h.userID, ConnectionID: connection.ID, AccessKeyID: key.ID}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/proxy/legacy", bytes.NewReader(body))
	for name, value := range map[string]string{"X-Api-Key": h.secret, "Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "subscriptions/listen"} {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte("notifications/progress")) || !bytes.Contains(rec.Body.Bytes(), []byte("event: result")) || !bytes.Contains(rec.Body.Bytes(), []byte(`"value":"legacy"`)) || !bytes.Contains(rec.Body.Bytes(), []byte(`"resultType":"complete"`)) {
		t.Fatalf("legacy SSE %d: %s", rec.Code, rec.Body)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(`"cacheScope"`)) {
		t.Fatalf("non-list legacy SSE gained cache metadata: %s", rec.Body)
	}
	page := decode[mcpAuditPageResponse](t, h.do(t, http.MethodGet, "/api/v1/mcp/audit?connectionId="+connection.ID.String(), nil, true))
	if page.Total != 6 {
		t.Fatalf("legacy SSE audit total %d", page.Total)
	}
}

func TestMCPProxyLegacySessionSSERejectsInvalidResultBeforeHeaders(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case bytes.Contains(body, []byte(`"method":"initialize"`)):
			w.Header().Set("MCP-Session-Id", "legacy-session")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"dwv-legacy-initialize","result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"Legacy","version":"1"}}}`))
		case bytes.Contains(body, []byte(`"method":"notifications/initialized"`)):
			w.WriteHeader(http.StatusAccepted)
		default:
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":[]}\n\n"))
		}
	}))
	defer upstream.Close()
	h := newHarness(t)
	h.server.deps.MCPClient = upstream.Client()
	connection := createLegacyMCPConnection(t, h, upstream.URL)
	key := firstAccessKey(t, h)
	if err := h.ms.InsertMCPConnectionGrant(t.Context(), &store.MCPConnectionGrant{UserID: h.userID, ConnectionID: connection.ID, AccessKeyID: key.ID}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/proxy/legacy", bytes.NewReader(body))
	for name, value := range map[string]string{"X-Api-Key": h.secret, "Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "subscriptions/listen"} {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway || strings.HasPrefix(rec.Header().Get("Content-Type"), "text/event-stream") || !bytes.Contains(rec.Body.Bytes(), []byte(`"error"`)) {
		t.Fatalf("legacy invalid SSE %d headers=%v body=%s", rec.Code, rec.Header(), rec.Body)
	}
}
