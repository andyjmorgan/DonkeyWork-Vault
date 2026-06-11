package restclient

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestFetchMe_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/me" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("X-Api-Key") != "k" {
			t.Errorf("missing X-Api-Key, got %q", r.Header.Get("X-Api-Key"))
		}
		_, _ = w.Write([]byte(`{"userId":"u","tenantId":"t","email":"e@x","name":"N"}`))
	}))
	defer srv.Close()

	// Trailing slash on baseURL must be trimmed.
	me, err := FetchMe(srv.URL+"/", "k")
	if err != nil {
		t.Fatalf("FetchMe: %v", err)
	}
	if me.UserID != "u" || me.Email != "e@x" || me.Name != "N" || me.TenantID != "t" {
		t.Fatalf("got %+v", me)
	}
}

func TestFetchMeBearer_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("authz = %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"userId":"u"}`))
	}))
	defer srv.Close()

	me, err := FetchMeBearer(srv.URL, "tok")
	if err != nil {
		t.Fatalf("FetchMeBearer: %v", err)
	}
	if me.UserID != "u" {
		t.Fatalf("got %+v", me)
	}
}

func TestFetchMe_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	_, err := FetchMe(srv.URL, "bad")
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("want rejected error, got %v", err)
	}
}

func TestFetchMe_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := FetchMe(srv.URL, "bad")
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("want rejected error, got %v", err)
	}
}

func TestFetchMe_OtherNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := FetchMe(srv.URL, "k")
	if err == nil || strings.Contains(err.Error(), "rejected") {
		t.Fatalf("want generic GET error, got %v", err)
	}
}

func TestFetchMe_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	_, err := FetchMe(srv.URL, "k")
	if err == nil || !strings.Contains(err.Error(), "parse /me") {
		t.Fatalf("want parse error, got %v", err)
	}
}

func TestFetchMe_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	addr := srv.URL
	srv.Close() // nothing is listening now
	if _, err := FetchMe(addr, "k"); err == nil {
		t.Fatal("expected network error")
	}
}

func TestFetchMe_BadURL(t *testing.T) {
	if _, err := FetchMe("http://%zz", "k"); err == nil {
		t.Fatal("expected request-build error for bad URL")
	}
}

func TestFetchConfig_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/config" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"authority":"https://auth","clientId":"c","scopes":"s","authEnabled":true,"cliClientId":"cc","cliScopes":"cs","requireHttpsMetadata":true}`))
	}))
	defer srv.Close()

	cfg, err := FetchConfig(srv.URL + "/")
	if err != nil {
		t.Fatalf("FetchConfig: %v", err)
	}
	if cfg.Authority != "https://auth" || !cfg.AuthEnabled || cfg.CliClientID != "cc" || !cfg.RequireHTTPSMetadata {
		t.Fatalf("got %+v", cfg)
	}
}

func TestFetchConfig_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := FetchConfig(srv.URL); err == nil {
		t.Fatal("expected non-2xx error")
	}
}

func TestFetchConfig_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()
	_, err := FetchConfig(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "parse /api/config") {
		t.Fatalf("want parse error, got %v", err)
	}
}

func TestFetchConfig_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	addr := srv.URL
	srv.Close()
	if _, err := FetchConfig(addr); err == nil {
		t.Fatal("expected network error")
	}
}

func TestFetchConfig_BadURL(t *testing.T) {
	if _, err := FetchConfig("http://%zz"); err == nil {
		t.Fatal("expected request-build error")
	}
}

func TestPostForm_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("content-type = %q", ct)
		}
		if r.Header.Get("User-Agent") != "dwvault" {
			t.Errorf("user-agent = %q", r.Header.Get("User-Agent"))
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.Form.Get("grant_type") != "x" {
			t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	body, status, err := PostForm(srv.URL, map[string]string{"grant_type": "x", "k": "v"})
	if err != nil {
		t.Fatalf("PostForm: %v", err)
	}
	if status != http.StatusCreated || string(body) != "ok" {
		t.Fatalf("status=%d body=%q", status, body)
	}
}

func TestPostForm_Non2xxReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid"}`))
	}))
	defer srv.Close()
	// PostForm returns status+body without erroring on non-2xx; the caller decides.
	body, status, err := PostForm(srv.URL, nil)
	if err != nil {
		t.Fatalf("PostForm: %v", err)
	}
	if status != http.StatusBadRequest || !strings.Contains(string(body), "invalid") {
		t.Fatalf("status=%d body=%q", status, body)
	}
}

func TestPostForm_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	addr := srv.URL
	srv.Close()
	if _, _, err := PostForm(addr, map[string]string{"a": "b"}); err == nil {
		t.Fatal("expected network error")
	}
}

func TestPostForm_BadURL(t *testing.T) {
	if _, _, err := PostForm("http://%zz", nil); err == nil {
		t.Fatal("expected request-build error")
	}
	// sanity: url.Values still encodes (guards against accidental import removal)
	_ = url.Values{}
}
