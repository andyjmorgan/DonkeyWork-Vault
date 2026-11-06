package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// wantSecurityHeaders is the exact set the securityHeaders middleware must set on every response.
var wantSecurityHeaders = map[string]string{
	"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	"X-Content-Type-Options":    "nosniff",
	"X-Frame-Options":           "DENY",
	"Referrer-Policy":           "no-referrer",
}

func TestSecurityHeadersOnRouter(t *testing.T) {
	h := newHarness(t)

	// The middleware is outermost, so the headers must be present regardless of status: a healthy
	// 200, an unauthenticated 401, and a 404 all flow through it.
	cases := []struct {
		name   string
		method string
		path   string
		auth   bool
	}{
		{"healthz", "GET", "/healthz", false},
		{"authed api", "GET", "/api/v1/me", true},
		{"unauthorized api", "GET", "/api/v1/me", false},
		{"not found", "GET", "/does-not-exist", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := h.do(t, tc.method, tc.path, nil, tc.auth)
			for name, want := range wantSecurityHeaders {
				if got := rec.Header().Get(name); got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
		})
	}
}

func TestSecurityHeadersCallsNext(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	})

	rec := httptest.NewRecorder()
	securityHeaders(next).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if !called {
		t.Fatal("securityHeaders did not call next")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
	for name, want := range wantSecurityHeaders {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}
