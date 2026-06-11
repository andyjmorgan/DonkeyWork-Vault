package oauthdevice

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- Discover ---

func TestDiscover_Success(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(Discovery{ //nolint:gosec // G101: these are OIDC endpoint URLs in a test fixture, not credentials
			Issuer:                      "https://iss",
			DeviceAuthorizationEndpoint: "https://iss/device",
			TokenEndpoint:               "https://iss/token",
		})
	}))
	defer srv.Close()

	// Trailing slash trimmed.
	d, err := Discover(srv.URL + "/")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if gotPath != "/.well-known/openid-configuration" {
		t.Fatalf("path = %q", gotPath)
	}
	if d.TokenEndpoint != "https://iss/token" || d.DeviceAuthorizationEndpoint != "https://iss/device" {
		t.Fatalf("got %+v", d)
	}
}

func TestDiscover_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := Discover(srv.URL); err == nil {
		t.Fatal("expected non-2xx error")
	}
}

func TestDiscover_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	if _, err := Discover(srv.URL); err == nil {
		t.Fatal("expected json error")
	}
}

func TestDiscover_MissingEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Discovery{Issuer: "https://iss"}) // no endpoints
	}))
	defer srv.Close()
	_, err := Discover(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "device authorization") {
		t.Fatalf("want advertise error, got %v", err)
	}
}

func TestDiscover_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	addr := srv.URL
	srv.Close()
	if _, err := Discover(addr); err == nil {
		t.Fatal("expected network error")
	}
}

func TestDiscover_BadURL(t *testing.T) {
	if _, err := Discover("http://%zz"); err == nil {
		t.Fatal("expected request-build error")
	}
}

// --- Start ---

func TestStart_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.Form.Get("client_id") != "cid" {
			t.Errorf("client_id = %q", r.Form.Get("client_id"))
		}
		if r.Form.Get("code_challenge_method") != "S256" {
			t.Errorf("method = %q", r.Form.Get("code_challenge_method"))
		}
		// challenge must be the S256 of a (caller-held) verifier; just confirm non-empty.
		if r.Form.Get("code_challenge") == "" {
			t.Error("missing code_challenge")
		}
		_ = json.NewEncoder(w).Encode(DeviceStart{
			DeviceCode: "dc", UserCode: "UC", VerificationURI: "https://v",
			ExpiresIn: 600, Interval: 0, // 0 → defaulted to 5
		})
	}))
	defer srv.Close()

	d := &Discovery{DeviceAuthorizationEndpoint: srv.URL, TokenEndpoint: srv.URL}
	start, err := Start(d, "cid", "openid")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if start.DeviceCode != "dc" || start.CodeVerifier == "" {
		t.Fatalf("got %+v", start)
	}
	if start.Interval != 5 {
		t.Fatalf("interval default = %d, want 5", start.Interval)
	}
}

func TestStart_PreservesInterval(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(DeviceStart{DeviceCode: "dc", ExpiresIn: 10, Interval: 3})
	}))
	defer srv.Close()
	d := &Discovery{DeviceAuthorizationEndpoint: srv.URL}
	start, err := Start(d, "cid", "openid")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if start.Interval != 3 {
		t.Fatalf("interval = %d, want 3 (preserved)", start.Interval)
	}
}

func TestStart_OAuthErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(TokenResponse{Error: "invalid_client", ErrorDescription: "bad"}) //nolint:gosec // G117: encoding a test TokenResponse fixture to the test server is intended
	}))
	defer srv.Close()
	d := &Discovery{DeviceAuthorizationEndpoint: srv.URL}
	_, err := Start(d, "cid", "openid")
	if err == nil {
		t.Fatal("expected oauth error")
	}
	var oe oauthErr
	if !errors.As(err, &oe) || oe.Code != "invalid_client" {
		t.Fatalf("want oauthErr invalid_client, got %v", err)
	}
}

func TestStart_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	d := &Discovery{DeviceAuthorizationEndpoint: srv.URL}
	if _, err := Start(d, "cid", "openid"); err == nil {
		t.Fatal("expected json error")
	}
}

func TestStart_PostFormError(t *testing.T) {
	d := &Discovery{DeviceAuthorizationEndpoint: "http://%zz"}
	if _, err := Start(d, "cid", "openid"); err == nil {
		t.Fatal("expected PostForm error from bad endpoint")
	}
}

// --- Poll ---

func TestPoll_PendingThenSlowDownThenSuccess(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		switch calls {
		case 1:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(TokenResponse{Error: "authorization_pending"}) //nolint:gosec // G117: encoding a test TokenResponse fixture to the test server is intended
		case 2:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(TokenResponse{Error: "slow_down"}) //nolint:gosec // G117: encoding a test TokenResponse fixture to the test server is intended
		default:
			_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "at", RefreshToken: "rt", ExpiresIn: 60}) //nolint:gosec // G117: encoding a test TokenResponse fixture to the test server is intended
		}
	}))
	defer srv.Close()

	d := &Discovery{TokenEndpoint: srv.URL}
	// Interval 0 → time.Sleep(0); ExpiresIn large so deadline isn't hit.
	start := &DeviceStart{DeviceCode: "dc", CodeVerifier: "v", ExpiresIn: 60, Interval: 0}

	var notified int
	tok, err := Poll(d, "cid", start, func(time.Duration) { notified++ })
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if tok.AccessToken != "at" {
		t.Fatalf("got %+v", tok)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
	if notified == 0 {
		t.Fatal("notify never called")
	}
}

func TestPoll_TerminalError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(TokenResponse{Error: "access_denied", ErrorDescription: "no"}) //nolint:gosec // G117: encoding a test TokenResponse fixture to the test server is intended
	}))
	defer srv.Close()
	d := &Discovery{TokenEndpoint: srv.URL}
	start := &DeviceStart{DeviceCode: "dc", ExpiresIn: 60, Interval: 0}
	_, err := Poll(d, "cid", start, nil)
	var oe oauthErr
	if !errors.As(err, &oe) || oe.Code != "access_denied" {
		t.Fatalf("want access_denied oauthErr, got %v", err)
	}
}

func TestPoll_NonOAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// 2xx but missing access_token → token() returns a plain (non-oauthErr) error,
		// which Poll surfaces immediately.
		_ = json.NewEncoder(w).Encode(TokenResponse{TokenType: "bearer"}) //nolint:gosec // G117: encoding a test TokenResponse fixture to the test server is intended
	}))
	defer srv.Close()
	d := &Discovery{TokenEndpoint: srv.URL}
	start := &DeviceStart{DeviceCode: "dc", ExpiresIn: 60, Interval: 0}
	_, err := Poll(d, "cid", start, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var oe oauthErr
	if errors.As(err, &oe) {
		t.Fatalf("expected non-oauth error, got oauthErr %v", err)
	}
}

func TestPoll_Expired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(TokenResponse{Error: "authorization_pending"}) //nolint:gosec // G117: encoding a test TokenResponse fixture to the test server is intended
	}))
	defer srv.Close()
	d := &Discovery{TokenEndpoint: srv.URL}
	// ExpiresIn 0 → deadline is now; the after-sleep check fires before any token call.
	start := &DeviceStart{DeviceCode: "dc", ExpiresIn: 0, Interval: 0}
	_, err := Poll(d, "cid", start, nil)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("want expired error, got %v", err)
	}
}

// --- Refresh ---

func TestRefresh_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse: %v", err)
		}
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "rt" {
			t.Errorf("form = %v", r.Form)
		}
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "new-at", RefreshToken: "new-rt"}) //nolint:gosec // G117: encoding a test TokenResponse fixture to the test server is intended
	}))
	defer srv.Close()

	tok, err := Refresh(srv.URL, "cid", "rt")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if tok.AccessToken != "new-at" {
		t.Fatalf("got %+v", tok)
	}
}

func TestRefresh_OAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(TokenResponse{Error: "invalid_grant"}) //nolint:gosec // G117: encoding a test TokenResponse fixture to the test server is intended
	}))
	defer srv.Close()
	_, err := Refresh(srv.URL, "cid", "rt")
	var oe oauthErr
	if !errors.As(err, &oe) || oe.Code != "invalid_grant" {
		t.Fatalf("want invalid_grant, got %v", err)
	}
}

// --- token (covered via Refresh paths above; add the bad-JSON and net error cases) ---

func TestToken_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	if _, err := Refresh(srv.URL, "cid", "rt"); err == nil {
		t.Fatal("expected json error")
	}
}

func TestToken_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	addr := srv.URL
	srv.Close()
	if _, err := Refresh(addr, "cid", "rt"); err == nil {
		t.Fatal("expected network error")
	}
}

// --- DecodeClaims ---

func encodeJWT(payload string) string {
	seg := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return "header." + seg + ".sig"
}

func TestDecodeClaims_Valid(t *testing.T) {
	tok := encodeJWT(`{"sub":"s1","email":"e@x","preferred_username":"u"}`)
	c := DecodeClaims(tok)
	if c.Subject != "s1" || c.Email != "e@x" || c.PreferredUsername != "u" {
		t.Fatalf("got %+v", c)
	}
}

func TestDecodeClaims_TooFewParts(t *testing.T) {
	if c := DecodeClaims("onlyonepart"); c != (Claims{}) {
		t.Fatalf("want empty, got %+v", c)
	}
}

func TestDecodeClaims_BadBase64(t *testing.T) {
	if c := DecodeClaims("h.!!!not-base64!!!.s"); c != (Claims{}) {
		t.Fatalf("want empty, got %+v", c)
	}
}

func TestDecodeClaims_BadJSON(t *testing.T) {
	tok := encodeJWT("not json")
	if c := DecodeClaims(tok); c != (Claims{}) {
		t.Fatalf("want empty, got %+v", c)
	}
}

// --- oauthErr.Error ---

func TestOauthErr_Error(t *testing.T) {
	if got := (oauthErr{Code: "c", Description: "d"}).Error(); got != "c: d" {
		t.Fatalf("got %q", got)
	}
	if got := (oauthErr{Code: "c"}).Error(); got != "c" {
		t.Fatalf("got %q", got)
	}
}

// --- oauthError fallback when body isn't an OAuth error doc ---

func TestStart_NonOAuthErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("plain text gateway error"))
	}))
	defer srv.Close()
	d := &Discovery{DeviceAuthorizationEndpoint: srv.URL}
	_, err := Start(d, "cid", "openid")
	if err == nil {
		t.Fatal("expected error")
	}
	var oe oauthErr
	if errors.As(err, &oe) {
		t.Fatalf("body had no error field; want plain error, got oauthErr %v", err)
	}
	if !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("want HTTP 502 fallback, got %v", err)
	}
}

// --- pkce ---

func TestPKCE_ChallengeIsS256OfVerifier(t *testing.T) {
	v, c, err := pkce()
	if err != nil {
		t.Fatalf("pkce: %v", err)
	}
	sum := sha256.Sum256([]byte(v))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if c != want {
		t.Fatalf("challenge mismatch: %q vs %q", c, want)
	}
	if v == "" {
		t.Fatal("empty verifier")
	}
}
