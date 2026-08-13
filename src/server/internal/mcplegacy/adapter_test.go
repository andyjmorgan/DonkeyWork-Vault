package mcplegacy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func legacyRequest(t *testing.T, endpoint, token string) *http.Request {
	return legacyRequestContext(t.Context(), t, endpoint, token)
}

func legacyRequestContext(ctx context.Context, t *testing.T, endpoint, token string) *http.Request {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"x","_meta":{"progressToken":"p","io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"eval","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Mcp-Method", "tools/list")
	request.Header.Set("Mcp-Name", "remove")
	request.Header.Set("Mcp-Param-X", "remove")
	request.Header.Set("Last-Event-ID", "remove")
	return request
}

func initializeResponse(session string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("MCP-Session-Id", session)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"dwv-legacy-initialize","result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"upstream","version":"1"}}}`))
	}
}

func newAdapter(t *testing.T, endpoint string, client *http.Client, mutate func(*Config)) *Adapter {
	t.Helper()
	config := Config{Endpoint: endpoint, Client: client, ClientName: "DonkeyWork Vault", ClientVersion: "test", MaxConcurrent: 4}
	if mutate != nil {
		mutate(&config)
	}
	adapter, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func TestAdapterInitializeTranslateAndReuseSession(t *testing.T) {
	var mu sync.Mutex
	var methods, auth []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var method string
		switch {
		case bytes.Contains(body, []byte(`"method":"initialize"`)):
			if r.Header.Get("MCP-Session-Id") != "" {
				t.Error("initialize carried a session")
			}
			initializeResponse("session-1")(w, r)
			return
		case bytes.Contains(body, []byte(`"method":"notifications/initialized"`)):
			method = "initialized"
			w.WriteHeader(http.StatusAccepted)
		case bytes.Contains(body, []byte(`"method":"tools/list"`)):
			method = "tools/list"
			if bytes.Contains(body, []byte("protocolVersion")) || bytes.Contains(body, []byte("clientCapabilities")) || !bytes.Contains(body, []byte(`"progressToken":"p"`)) {
				t.Errorf("modern metadata not translated correctly: %s", body)
			}
			if r.Header.Get("Mcp-Method") != "" || r.Header.Get("Mcp-Name") != "" || r.Header.Get("Mcp-Param-X") != "" || r.Header.Get("Last-Event-ID") != "" {
				t.Errorf("modern headers leaked: %v", r.Header)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
		default:
			t.Fatalf("unknown body: %s", body)
		}
		if r.Header.Get("MCP-Protocol-Version") != "2025-06-18" || method != "initialize" && r.Header.Get("MCP-Session-Id") != "session-1" {
			t.Errorf("legacy headers missing for %s: %v", method, r.Header)
		}
		mu.Lock()
		methods, auth = append(methods, method), append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	defer server.Close()
	adapter := newAdapter(t, server.URL, server.Client(), nil)
	for _, token := range []string{"first", "rotated"} {
		response, err := adapter.Do(t.Context(), legacyRequest(t, server.URL, token))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(response.Body)
		_ = response.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(methods, ",") != "initialized,tools/list,tools/list" {
		t.Fatalf("unexpected sequence: %#v", methods)
	}
	if auth[0] != "Bearer first" || auth[1] != "Bearer first" || auth[2] != "Bearer rotated" {
		t.Fatalf("credentials retained or lost: %#v", auth)
	}
}

func TestAdapterReinitializesOnceOnSession404(t *testing.T) {
	var initializes, operations atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case bytes.Contains(body, []byte(`"method":"initialize"`)):
			n := initializes.Add(1)
			initializeResponse("session-"+strconv.FormatInt(int64(n), 10))(w, r)
		case bytes.Contains(body, []byte(`"method":"notifications/initialized"`)):
			w.WriteHeader(http.StatusAccepted)
		default:
			n := operations.Add(1)
			if n == 1 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Header.Get("MCP-Session-Id") != "session-2" {
				t.Errorf("retry used wrong session: %q", r.Header.Get("MCP-Session-Id"))
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		}
	}))
	defer server.Close()
	adapter := newAdapter(t, server.URL, server.Client(), nil)
	response, err := adapter.Do(t.Context(), legacyRequest(t, server.URL, "token"))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if initializes.Load() != 2 || operations.Load() != 2 {
		t.Fatalf("initializes=%d operations=%d", initializes.Load(), operations.Load())
	}
}

func TestAdapterDoesNotRetryOtherResponsesOrSessionless404(t *testing.T) {
	for _, test := range []struct {
		name, session string
		status        int
	}{
		{"bad request", "session", http.StatusBadRequest},
		{"server error", "session", http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			var operations atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				switch {
				case bytes.Contains(body, []byte(`"method":"initialize"`)):
					initializeResponse(test.session)(w, r)
				case bytes.Contains(body, []byte(`"method":"notifications/initialized"`)):
					w.WriteHeader(http.StatusAccepted)
				default:
					operations.Add(1)
					w.WriteHeader(test.status)
				}
			}))
			defer server.Close()
			adapter := newAdapter(t, server.URL, server.Client(), nil)
			response, err := adapter.Do(t.Context(), legacyRequest(t, server.URL, "token"))
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != test.status || operations.Load() != 1 {
				t.Fatalf("status=%d operations=%d", response.StatusCode, operations.Load())
			}
		})
	}
}

func TestAdapterConcurrentInitializationAndBound(t *testing.T) {
	var initializes, active, maximum atomic.Int32
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case bytes.Contains(body, []byte(`"method":"initialize"`)):
			initializes.Add(1)
			initializeResponse("session")(w, r)
		case bytes.Contains(body, []byte(`"method":"notifications/initialized"`)):
			w.WriteHeader(http.StatusAccepted)
		default:
			n := active.Add(1)
			for {
				old := maximum.Load()
				if n <= old || maximum.CompareAndSwap(old, n) {
					break
				}
			}
			<-release
			active.Add(-1)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		}
	}))
	defer server.Close()
	adapter := newAdapter(t, server.URL, server.Client(), func(c *Config) { c.MaxConcurrent = 2 })
	errCh := make(chan error, 5)
	for range 5 {
		go func() {
			response, err := adapter.Do(t.Context(), legacyRequest(t, server.URL, "token"))
			if err == nil {
				_ = response.Body.Close()
			}
			errCh <- err
		}()
	}
	deadline := time.After(2 * time.Second)
	for maximum.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("requests did not reach concurrency limit")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(release)
	for range 5 {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if initializes.Load() != 1 || maximum.Load() != 2 {
		t.Fatalf("initializes=%d max=%d", initializes.Load(), maximum.Load())
	}
}

func TestAdapterExpireIdleAndClose(t *testing.T) {
	var initializes, deletes atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes.Add(1)
			if r.Header.Get("Authorization") != "Bearer close-token" || r.Header.Get("MCP-Session-Id") != "session" {
				t.Errorf("bad close headers: %v", r.Header)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		body, _ := io.ReadAll(r.Body)
		switch {
		case bytes.Contains(body, []byte(`"method":"initialize"`)):
			initializes.Add(1)
			initializeResponse("session")(w, r)
		case bytes.Contains(body, []byte(`"method":"notifications/initialized"`)):
			w.WriteHeader(http.StatusAccepted)
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		}
	}))
	defer server.Close()
	adapter := newAdapter(t, server.URL, server.Client(), func(c *Config) { c.IdleTimeout = time.Second })
	response, err := adapter.Do(t.Context(), legacyRequest(t, server.URL, "one"))
	if err != nil {
		t.Fatal(err)
	}
	if adapter.ExpireIdle(time.Now().Add(time.Hour)) {
		t.Fatal("active response expired")
	}
	_ = response.Body.Close()
	if !adapter.ExpireIdle(time.Now().Add(time.Hour)) || adapter.ExpireIdle(time.Now().Add(2*time.Hour)) {
		t.Fatal("idle expiration mismatch")
	}
	response, err = adapter.Do(t.Context(), legacyRequest(t, server.URL, "two"))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if initializes.Load() != 2 {
		t.Fatalf("initializations=%d", initializes.Load())
	}
	if err := adapter.Close(t.Context(), legacyRequest(t, server.URL, "close-token")); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Close(t.Context(), nil); err != nil || deletes.Load() != 1 {
		t.Fatalf("idempotent close err=%v deletes=%d", err, deletes.Load())
	}
	response, err = adapter.Do(t.Context(), legacyRequest(t, server.URL, "after"))
	if response != nil {
		_ = response.Body.Close()
	}
	if !IsErrorKind(err, ErrorClosed) {
		t.Fatalf("got %v", err)
	}
}

func TestAdapterErrors(t *testing.T) {
	client := &http.Client{}
	invalidConfigs := []Config{
		{}, {Endpoint: "http://example.com", Client: client, ClientName: "x", ClientVersion: "1"},
		{Endpoint: "https://example.com", Client: client},
		{Endpoint: "https://example.com", Client: client, ClientName: "x", ClientVersion: "1", IdleTimeout: -1},
	}
	for _, config := range invalidConfigs {
		if _, err := New(config); !IsErrorKind(err, ErrorInvalidConfig) {
			t.Errorf("config %+v: %v", config, err)
		}
	}
	adapter, _ := New(Config{Endpoint: "https://example.com", Client: client, ClientName: "x", ClientVersion: "1"})
	response, err := adapter.Do(t.Context(), nil)
	if response != nil {
		_ = response.Body.Close()
	}
	if !IsErrorKind(err, ErrorInvalidRequest) {
		t.Fatalf("nil request: %v", err)
	}
	for _, body := range []string{"{", `[]`, `{}`, `{"method":"x"}{}`} {
		request, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com", strings.NewReader(body))
		response, err := adapter.Do(t.Context(), request)
		if response != nil {
			_ = response.Body.Close()
		}
		if !IsErrorKind(err, ErrorInvalidRequest) {
			t.Errorf("body %q: %v", body, err)
		}
	}
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com", strings.NewReader(`{"method":"x","params":[]}`))
	response, err = adapter.Do(t.Context(), request)
	if response != nil {
		_ = response.Body.Close()
	}
	if !IsErrorKind(err, ErrorInvalidRequest) {
		t.Fatalf("array params: %v", err)
	}
	request, _ = http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com", strings.NewReader(`{"method":"x","params":{"_meta":[]}}`))
	response, err = adapter.Do(t.Context(), request)
	if response != nil {
		_ = response.Body.Close()
	}
	if !IsErrorKind(err, ErrorInvalidRequest) {
		t.Fatalf("array meta: %v", err)
	}
	request, _ = http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com", strings.NewReader(strings.Repeat("x", int(defaultMaxBodyBytes+1))))
	response, err = adapter.Do(t.Context(), request)
	if response != nil {
		_ = response.Body.Close()
	}
	if !IsErrorKind(err, ErrorResponseTooLarge) {
		t.Fatalf("oversized request: %v", err)
	}
	if err := (&Error{Kind: ErrorInvalidRequest, err: io.EOF}).Error(); !strings.Contains(err, "invalid_request") {
		t.Fatal(err)
	}
	if !errors.Is(&Error{Kind: ErrorInvalidRequest, err: io.EOF}, io.EOF) {
		t.Fatal("error does not unwrap")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read failure") }

type errorReadCloser struct{ errorReader }

func (errorReadCloser) Close() error { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func TestReadAndResponseValidationEdges(t *testing.T) {
	if _, err := readBounded(errorReader{}, 10); err == nil {
		t.Fatal("read error lost")
	}
	invalidResponses := []string{
		`{"jsonrpc":"2.0","id":"dwv-legacy-initialize","result":{"protocolVersion":"2025-06-18","capabilities":null,"serverInfo":{"name":"x","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":"dwv-legacy-initialize","result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":null}}`,
		`{"jsonrpc":"2.0","id":"wrong","result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"x","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":"dwv-legacy-initialize","result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":"dwv-legacy-initialize","error":{"code":1,"message":"x"}}`,
		`{"jsonrpc":"2.0","id":"dwv-legacy-initialize","result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"x","version":"1"}}}{}`,
	}
	for _, body := range invalidResponses {
		if err := validateInitializeResponse([]byte(body), "2025-06-18"); !IsErrorKind(err, ErrorInvalidInitialize) {
			t.Errorf("body %s: %v", body, err)
		}
	}
	if validSessionID("") || validSessionID("bad\n") || !validSessionID("session") {
		t.Fatal("session validation mismatch")
	}
}

func TestInitializeResponseTooLarge(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("MCP-Session-Id", "session")
		_, _ = w.Write(bytes.Repeat([]byte{'x'}, 17))
	}))
	defer server.Close()
	adapter := newAdapter(t, server.URL, server.Client(), func(config *Config) { config.MaxBodyBytes = 16 })
	response, err := adapter.Do(t.Context(), legacyRequest(t, server.URL, "token"))
	if response != nil {
		_ = response.Body.Close()
	}
	if !IsErrorKind(err, ErrorResponseTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func TestTransportFailures(t *testing.T) {
	closed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	client, endpoint := closed.Client(), closed.URL
	closed.Close()
	adapter := newAdapter(t, endpoint, client, nil)
	response, err := adapter.Do(t.Context(), legacyRequest(t, endpoint, "token"))
	if response != nil {
		_ = response.Body.Close()
	}
	if !IsErrorKind(err, ErrorTransport) {
		t.Fatalf("initialize transport: %v", err)
	}

	var phase atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte(`"method":"initialize"`)) {
			initializeResponse("session")(w, r)
			return
		}
		if bytes.Contains(body, []byte("notifications/initialized")) {
			w.WriteHeader(202)
			return
		}
		phase.Add(1)
		panic(http.ErrAbortHandler)
	}))
	adapter = newAdapter(t, server.URL, server.Client(), nil)
	response, err = adapter.Do(t.Context(), legacyRequest(t, server.URL, "token"))
	if response != nil {
		_ = response.Body.Close()
	}
	if !IsErrorKind(err, ErrorTransport) {
		t.Fatalf("operation transport: %v", err)
	}
	server.Close()

	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte(`"method":"initialize"`)) {
			initializeResponse("session")(w, r)
			return
		}
		panic(http.ErrAbortHandler)
	}))
	adapter = newAdapter(t, server.URL, server.Client(), nil)
	response, err = adapter.Do(t.Context(), legacyRequest(t, server.URL, "token"))
	if response != nil {
		_ = response.Body.Close()
	}
	if !IsErrorKind(err, ErrorTransport) {
		t.Fatalf("initialized transport: %v", err)
	}
	server.Close()
}

func TestOperationReinitializeFailure(t *testing.T) {
	var initializes atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte(`"method":"initialize"`)) {
			if initializes.Add(1) == 1 {
				initializeResponse("session")(w, r)
			} else {
				w.WriteHeader(400)
			}
			return
		}
		if bytes.Contains(body, []byte("notifications/initialized")) {
			w.WriteHeader(202)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()
	adapter := newAdapter(t, server.URL, server.Client(), nil)
	response, err := adapter.Do(t.Context(), legacyRequest(t, server.URL, "token"))
	if response != nil {
		_ = response.Body.Close()
	}
	if !IsErrorKind(err, ErrorInitializeRejected) {
		t.Fatalf("got %v", err)
	}
}

func TestCloseContextAndWithoutSession(t *testing.T) {
	adapter := newAdapter(t, "https://example.com", &http.Client{}, nil)
	if err := adapter.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte("initialize")) {
			initializeResponse("session")(w, r)
			return
		}
		if bytes.Contains(body, []byte("initialized")) {
			w.WriteHeader(202)
			return
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	adapter = newAdapter(t, server.URL, server.Client(), func(config *Config) { config.MaxConcurrent = 2 })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		response, _ := adapter.Do(ctx, legacyRequestContext(ctx, t, server.URL, "token"))
		if response != nil {
			_ = response.Body.Close()
		}
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	closeCtx, closeCancel := context.WithCancel(context.Background())
	closeCancel()
	if err := adapter.Close(closeCtx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	cancel()
	<-done
}

func TestRequestReadAndCloseTransportFailures(t *testing.T) {
	adapter := newAdapter(t, "https://example.com", &http.Client{}, nil)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com", strings.NewReader("unused"))
	if err != nil {
		t.Fatal(err)
	}
	request.Body = errorReadCloser{}
	response, err := adapter.Do(t.Context(), request)
	if response != nil {
		_ = response.Body.Close()
	}
	if !IsErrorKind(err, ErrorInvalidRequest) {
		t.Fatalf("request read: %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case bytes.Contains(body, []byte(`"method":"initialize"`)):
			initializeResponse("session")(w, r)
		case bytes.Contains(body, []byte("notifications/initialized")):
			w.WriteHeader(http.StatusAccepted)
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		}
	}))
	adapter = newAdapter(t, server.URL, server.Client(), nil)
	response, err = adapter.Do(t.Context(), legacyRequest(t, server.URL, "token"))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	template := legacyRequest(t, server.URL, "token")
	server.Close()
	if err := adapter.Close(t.Context(), template); !IsErrorKind(err, ErrorTransport) {
		t.Fatalf("close transport: %v", err)
	}
}

func TestInitializeResponseReadFailure(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: errorReadCloser{}}, nil
	})}
	adapter := newAdapter(t, "https://example.com", client, nil)
	response, err := adapter.Do(t.Context(), legacyRequest(t, "https://example.com", "token"))
	if response != nil {
		_ = response.Body.Close()
	}
	if !IsErrorKind(err, ErrorTransport) {
		t.Fatalf("got %v", err)
	}
}

func TestAcquireDetectsConcurrentClose(t *testing.T) {
	adapter := newAdapter(t, "https://example.com", &http.Client{}, func(config *Config) { config.MaxConcurrent = 1 })
	adapter.permits <- struct{}{}
	done := make(chan error, 1)
	go func() { done <- adapter.acquire(t.Context()) }()
	time.Sleep(10 * time.Millisecond)
	adapter.mu.Lock()
	adapter.closed = true
	adapter.mu.Unlock()
	<-adapter.permits
	if err := <-done; !IsErrorKind(err, ErrorClosed) {
		t.Fatalf("got %v", err)
	}
}

func TestInitializeFailures(t *testing.T) {
	tests := []struct {
		name              string
		status            int
		body              string
		session           string
		initializedStatus int
		kind              ErrorKind
	}{
		{"rejected", 400, `{}`, "", 202, ErrorInitializeRejected},
		{"malformed", 200, `{}`, "session", 202, ErrorInvalidInitialize},
		{"wrong version", 200, `{"jsonrpc":"2.0","id":"dwv-legacy-initialize","result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"x","version":"1"}}}`, "session", 202, ErrorVersionMismatch},
		{"invalid session", 200, `{"jsonrpc":"2.0","id":"dwv-legacy-initialize","result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"x","version":"1"}}}`, "bad session", 202, ErrorInvalidInitialize},
		{"empty session", 200, `{"jsonrpc":"2.0","id":"dwv-legacy-initialize","result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"x","version":"1"}}}`, "", 202, ErrorInvalidInitialize},
		{"initialized rejected", 200, `{"jsonrpc":"2.0","id":"dwv-legacy-initialize","result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"x","version":"1"}}}`, "session", 400, ErrorInitializeRejected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if bytes.Contains(body, []byte("notifications/initialized")) {
					w.WriteHeader(test.initializedStatus)
					return
				}
				w.Header().Set("MCP-Session-Id", test.session)
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			adapter := newAdapter(t, server.URL, server.Client(), nil)
			response, err := adapter.Do(t.Context(), legacyRequest(t, server.URL, "token"))
			if response != nil {
				_ = response.Body.Close()
			}
			if !IsErrorKind(err, test.kind) {
				t.Fatalf("got %v want %s", err, test.kind)
			}
		})
	}
}

func TestAdapterContextWhileWaiting(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte(`"method":"initialize"`)) {
			initializeResponse("session")(w, r)
			return
		}
		if bytes.Contains(body, []byte("notifications/initialized")) {
			w.WriteHeader(202)
			return
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	adapter := newAdapter(t, server.URL, server.Client(), func(c *Config) { c.MaxConcurrent = 1 })
	ctx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan struct{})
	go func() {
		response, _ := adapter.Do(ctx, legacyRequestContext(ctx, t, server.URL, "one"))
		if response != nil {
			_ = response.Body.Close()
		}
		close(firstDone)
	}()
	time.Sleep(20 * time.Millisecond)
	waitCtx, waitCancel := context.WithCancel(context.Background())
	waitCancel()
	request := legacyRequest(t, server.URL, "two").WithContext(waitCtx)
	response, err := adapter.Do(waitCtx, request)
	if response != nil {
		_ = response.Body.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	cancel()
	<-firstDone
}

func TestLifecycleObserverOrderCopiesAndFailsClosed(t *testing.T) {
	var sends atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sends.Add(1)
		body, _ := io.ReadAll(r.Body)
		switch {
		case bytes.Contains(body, []byte(`"method":"initialize"`)):
			initializeResponse("session")(w, r)
		case bytes.Contains(body, []byte("notifications/initialized")):
			w.WriteHeader(http.StatusAccepted)
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		}
	}))
	defer server.Close()

	adapter := newAdapter(t, server.URL, server.Client(), nil)
	var messages []LifecycleMessage
	response, err := adapter.DoObserved(t.Context(), legacyRequest(t, server.URL, "token"), func(message LifecycleMessage) error {
		messages = append(messages, message)
		if len(message.Body) != 0 {
			message.Body[0] = 'x'
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if len(messages) != 3 {
		t.Fatalf("messages=%d: %#v", len(messages), messages)
	}
	if messages[0].Direction != LifecycleToUpstream || messages[0].Method != "initialize" ||
		messages[1].Direction != LifecycleFromUpstream || messages[1].Method != "initialize" ||
		messages[2].Direction != LifecycleToUpstream || messages[2].Method != "notifications/initialized" {
		t.Fatalf("unexpected lifecycle order: %#v", messages)
	}
	// Mutating an observed copy must not corrupt the request subsequently sent upstream.
	if sends.Load() != 3 {
		t.Fatalf("network sends=%d", sends.Load())
	}

	for _, failAt := range []int{1, 2, 3} {
		t.Run("failure "+strconv.Itoa(failAt), func(t *testing.T) {
			before := sends.Load()
			adapter := newAdapter(t, server.URL, server.Client(), nil)
			calls := 0
			response, err := adapter.DoObserved(t.Context(), legacyRequest(t, server.URL, "token"), func(LifecycleMessage) error {
				calls++
				if calls == failAt {
					return io.ErrUnexpectedEOF
				}
				return nil
			})
			if response != nil {
				_ = response.Body.Close()
			}
			if !IsErrorKind(err, ErrorObserver) || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("got %v", err)
			}
			// Audit failure happens before the corresponding outbound send. A response
			// observer failure occurs after initialize but before initialized.
			wantSends := []int32{0, 1, 1}[failAt-1]
			if got := sends.Load() - before; got != wantSends {
				t.Fatalf("network sends=%d want %d", got, wantSends)
			}
		})
	}
}

func TestInitializationWaiterReceivesFailureAndCanCancel(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case <-started:
		default:
			close(started)
		}
		<-release
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	adapter := newAdapter(t, server.URL, server.Client(), nil)

	firstErr := make(chan error, 1)
	go func() {
		response, err := adapter.Do(t.Context(), legacyRequest(t, server.URL, "one"))
		if response != nil {
			_ = response.Body.Close()
		}
		firstErr <- err
	}()
	<-started

	waitCtx, cancel := context.WithCancel(context.Background())
	canceledErr := make(chan error, 1)
	go func() {
		request := legacyRequestContext(waitCtx, t, server.URL, "two")
		response, err := adapter.Do(waitCtx, request)
		if response != nil {
			_ = response.Body.Close()
		}
		canceledErr <- err
	}()
	cancel()
	if err := <-canceledErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter: %v", err)
	}

	waiterErr := make(chan error, 1)
	go func() {
		response, err := adapter.Do(t.Context(), legacyRequest(t, server.URL, "three"))
		if response != nil {
			_ = response.Body.Close()
		}
		waiterErr <- err
	}()
	time.Sleep(10 * time.Millisecond)
	close(release)
	if err := <-firstErr; !IsErrorKind(err, ErrorInitializeRejected) {
		t.Fatalf("initializer: %v", err)
	}
	if err := <-waiterErr; !IsErrorKind(err, ErrorInitializeRejected) {
		t.Fatalf("waiter: %v", err)
	}
}

func TestTranslationRemovesEmptyMetaAndRejectsInvalidTrailingJSON(t *testing.T) {
	translated, err := translateRequestBody([]byte(`{"jsonrpc":"2.0","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/logLevel":"debug"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(translated, []byte("_meta")) {
		t.Fatalf("empty metadata retained: %s", translated)
	}
	decoder := json.NewDecoder(strings.NewReader(`{} trailing`))
	var first json.RawMessage
	if err := decoder.Decode(&first); err != nil {
		t.Fatal(err)
	}
	if err := ensureJSONEOF(decoder); err == nil {
		t.Fatal("invalid trailing JSON accepted")
	}
}

func FuzzTranslateRequestBody(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(_ *testing.T, body []byte) {
		_, _ = translateRequestBody(body)
	})
}
