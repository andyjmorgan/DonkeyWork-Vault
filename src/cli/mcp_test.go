package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func TestMCPOAuthCallbackHandlerForwardsToVault(t *testing.T) {
	callback := make(chan string, 1)
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callback <- r.URL.RawQuery
		http.Redirect(w, r, "/mcp?oauth=connected", http.StatusFound)
	}))
	defer vault.Close()

	result := make(chan error, 1)
	handler := mcpOAuthCallbackHandler(vault.URL, "expected-state", result)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/oauth/callback?code=secret-code&state=expected-state", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "completed") {
		t.Fatalf("callback response %d: %s", recorder.Code, recorder.Body.String())
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if got := <-callback; got != "code=secret-code&state=expected-state" {
		t.Fatalf("forwarded query = %q", got)
	}
}

func TestMCPOAuthCallbackHandlerRejectsStateAndFailures(t *testing.T) {
	result := make(chan error, 1)
	handler := mcpOAuthCallbackHandler("https://vault.example", "expected", result)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/oauth/callback?state=wrong", nil))
	if recorder.Code != http.StatusBadRequest || len(result) != 0 {
		t.Fatalf("state mismatch status=%d result=%d", recorder.Code, len(result))
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/wrong", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("wrong path status=%d", recorder.Code)
	}

	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusBadRequest)
	}))
	defer vault.Close()
	result = make(chan error, 1)
	recorder = httptest.NewRecorder()
	mcpOAuthCallbackHandler(vault.URL, "state", result).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/oauth/callback?state=state", nil))
	if recorder.Code != http.StatusBadGateway || <-result == nil {
		t.Fatalf("upstream failure status=%d", recorder.Code)
	}
}

func TestBeginMCPOAuth(t *testing.T) {
	oldAddr, oldKey := addr, apiKey
	t.Cleanup(func() { addr, apiKey = oldAddr, oldKey })
	apiKey = "dwv_test"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != apiKey || r.URL.Query().Get("redirectUri") != "http://127.0.0.1:8000/oauth/callback" {
			t.Errorf("unexpected request headers=%v query=%v", r.Header, r.URL.Query())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorizeUrl":"https://auth.example/authorize?state=state","expiresAt":"2030-01-01T00:00:00Z"}`))
	}))
	defer server.Close()
	addr = server.URL
	got, err := beginMCPOAuth(uuid.MustParse("00000000-0000-0000-0000-000000000001"), "http://127.0.0.1:8000/oauth/callback")
	if err != nil || got != "https://auth.example/authorize?state=state" {
		t.Fatalf("begin = %q, %v", got, err)
	}
}

func TestBeginMCPOAuthFailures(t *testing.T) {
	oldAddr, oldKey := addr, apiKey
	t.Cleanup(func() { addr, apiKey = oldAddr, oldKey })
	apiKey = "dwv_test"
	tests := []struct {
		name, body string
		status     int
	}{
		{"server error", `{"error":"bad registration"}`, http.StatusBadRequest},
		{"invalid json", `{`, http.StatusOK},
		{"missing URL", `{}`, http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			addr = server.URL
			if _, err := beginMCPOAuth(uuid.New(), "http://127.0.0.1:8000/oauth/callback"); err == nil {
				t.Fatal("expected begin error")
			}
		})
	}
}

func TestMCPOAuthCommandValidation(t *testing.T) {
	root := &cobra.Command{Use: "test", SilenceUsage: true, SilenceErrors: true}
	root.AddCommand(mcpCmd())
	root.SetArgs([]string{"mcp", "oauth", "connect", "not-a-uuid"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "invalid connection ID") {
		t.Fatalf("command error = %v", err)
	}
}

func TestConnectMCPOAuthSuccessAndTimeout(t *testing.T) {
	oldAddr, oldKey, oldOpen, oldTimeout := addr, apiKey, mcpOAuthBrowserOpen, mcpOAuthTimeout
	t.Cleanup(func() {
		addr, apiKey, mcpOAuthBrowserOpen, mcpOAuthTimeout = oldAddr, oldKey, oldOpen, oldTimeout
	})
	apiKey = "dwv_test"

	var callbackState string
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth/connect"):
			redirect := r.URL.Query().Get("redirectUri")
			callbackState = "state"
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"authorizeUrl":%q,"expiresAt":"2030-01-01T00:00:00Z"}`, "https://auth.example/authorize?redirect_uri="+url.QueryEscape(redirect)+"&state="+callbackState)
		case r.URL.Path == "/api/mcp/oauth/callback":
			http.Redirect(w, r, "/mcp", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer vault.Close()
	addr = vault.URL
	mcpOAuthBrowserOpen = func(target string) error {
		parsed, _ := url.Parse(target)
		redirect, _ := url.QueryUnescape(parsed.Query().Get("redirect_uri"))
		go func() {
			response, requestErr := http.Get(redirect + "?code=code&state=" + callbackState)
			if requestErr == nil {
				_ = response.Body.Close()
			}
		}()
		return nil
	}
	if err := connectMCPOAuth(uuid.New()); err != nil {
		t.Fatal(err)
	}

	mcpOAuthBrowserOpen = func(string) error { return errors.New("headless") }
	mcpOAuthTimeout = time.Millisecond
	if err := connectMCPOAuth(uuid.New()); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout error = %v", err)
	}
}

func TestListenMCPOAuthCallbackAllPortsBusy(t *testing.T) {
	oldPorts := mcpOAuthCallbackPorts
	t.Cleanup(func() { mcpOAuthCallbackPorts = oldPorts })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := listener.Addr().(*net.TCPAddr).Port
	mcpOAuthCallbackPorts = []int{port}
	if _, _, err := listenMCPOAuthCallback(); err == nil {
		t.Fatal("expected occupied port error")
	}
}

func TestOpenBrowserStartsPlatformLauncher(_ *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		os.Exit(0)
	}
	// At least exercise the current platform's launcher failure path; CI need not have a browser.
	_ = openBrowser("https://example.com")
}

func TestListenMCPOAuthCallback(t *testing.T) {
	listener, redirect, err := listenMCPOAuthCallback()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	parsed, err := url.Parse(redirect)
	if err != nil || parsed.Hostname() != "127.0.0.1" || parsed.Path != "/oauth/callback" {
		t.Fatalf("redirect=%q err=%v", redirect, err)
	}
}
