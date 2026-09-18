package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"donkeywork.dev/vault-server/internal/contracts"
)

func TestXOAuthConnectAndRefresh(t *testing.T) {
	f := newOAuthFixture(t)
	var exchanges, refreshes int
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/me" {
			if r.Header.Get("Authorization") != "Bearer access-1" {
				t.Error("missing user access token")
			}
			_, _ = fmt.Fprint(w, `{"data":{"id":"123","name":"Alice","username":"alice"}}`)
			return
		}
		id, secret, ok := r.BasicAuth()
		if !ok || id != "client-id" || secret != "client-secret" {
			t.Error("missing client Basic auth")
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Has("client_secret") || r.Form.Has("client_id") {
			t.Error("client credentials duplicated in body")
		}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			exchanges++
			if r.Form.Get("code_verifier") == "" || r.Form.Get("redirect_uri") != "https://vault.example/api/oauth/callback" {
				t.Error("missing PKCE or callback")
			}
			_, _ = fmt.Fprint(w, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":7200,"scope":"tweet.read users.read offline.access"}`)
		case "refresh_token":
			refreshes++
			if r.Form.Get("refresh_token") != fmt.Sprintf("refresh-%d", refreshes) {
				t.Error("rotated refresh token not used")
			}
			_, _ = fmt.Fprintf(w, `{"access_token":"access-%d","refresh_token":"refresh-%d","expires_in":7200}`, refreshes+1, refreshes+1)
		default:
			t.Error("unexpected grant")
		}
	}))
	defer idp.Close()
	var found bool
	for _, m := range f.resolver.ListTemplates() {
		if m.Key != "x" {
			continue
		}
		found = true
		if m.TokenEndpointAuthMethod != "client_secret_basic" || m.UserinfoAccountPath != "data.username" {
			t.Fatal("incorrect X template")
		}
		m.TokenEndpoint, m.UserinfoEndpoint = idp.URL+"/token", idp.URL+"/me"
		if err := f.resolver.UpsertOAuth(f.ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	if !found {
		t.Fatal("X template missing")
	}
	if _, err := f.configs.Upsert(f.ctx, "x", "client-id", strPtr("client-secret"), []string{"tweet.read", "users.read", "offline.access"}, nil); err != nil {
		t.Fatal(err)
	}
	begin, err := f.flow.Begin(f.ctx, "x", nil, "https://vault.example")
	if err != nil {
		t.Fatal(err)
	}
	authURL, _ := url.Parse(begin.AuthorizeURL)
	if authURL.Host != "x.com" || authURL.Query().Get("code_challenge_method") != "S256" || authURL.Query().Get("scope") != "tweet.read users.read offline.access" {
		t.Fatalf("unexpected authorize URL: %s", begin.AuthorizeURL)
	}
	done, err := f.flow.Complete(context.Background(), "code", begin.State)
	if err != nil {
		t.Fatal(err)
	}
	if done.Account != "alice" {
		t.Fatalf("account = %q", done.Account)
	}
	for i := 0; i < 2; i++ {
		list, err := f.tokens.List(f.ctx)
		if err != nil || len(list) != 1 {
			t.Fatalf("tokens: %v %v", list, err)
		}
		row, err := f.ms.GetOAuthTokenByID(f.ctx, contracts.CallerFrom(f.ctx).UserID, list[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		past := time.Now().Add(-time.Hour)
		row.ExpiresAt = &past
		if err := f.ms.UpdateOAuthToken(f.ctx, row); err != nil {
			t.Fatal(err)
		}
		token, err := f.tokens.GetAccessToken(f.ctx, "x", "alice")
		if err != nil || token == nil || token.AccessToken != fmt.Sprintf("access-%d", i+2) {
			t.Fatalf("refresh failed: %v", err)
		}
	}
	if exchanges != 1 || refreshes != 2 {
		t.Fatalf("exchanges=%d refreshes=%d", exchanges, refreshes)
	}
}

func TestTokenEndpointAuthMethods(t *testing.T) {
	for _, method := range []string{"", "client_secret_post", "client_secret_basic", "unsupported"} {
		t.Run(method, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				_ = r.ParseForm()
				if method == "client_secret_basic" {
					id, secret, ok := r.BasicAuth()
					if !ok || id != url.QueryEscape("id:+") || secret != url.QueryEscape("secret /+") {
						t.Error("Basic credentials not form encoded")
					}
					if r.Form.Has("client_id") || r.Form.Has("client_secret") {
						t.Error("credentials leaked into body")
					}
				} else {
					if r.Header.Get("Authorization") != "" || r.Form.Get("client_id") != "id:+" {
						t.Error("incorrect client authentication")
					}
					if r.Form.Get("client_secret") != "secret /+" {
						t.Error("missing body secret")
					}
				}
				_, _ = fmt.Fprint(w, `{}`)
			}))
			defer server.Close()
			_, _, err := postForm(context.Background(), server.Client(), server.URL, url.Values{"client_id": {"id:+"}, "client_secret": {"secret /+"}}, method)
			if method == "unsupported" {
				if err == nil || !strings.Contains(err.Error(), "unsupported") || calls != 0 {
					t.Fatal("unsupported method not rejected")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUserinfoAccountPath(t *testing.T) {
	f := newOAuthFixture(t)
	for _, tc := range []struct{ path, body, want string }{
		{"data.username", `{"data":{"username":"alice"}}`, "alice"},
		{"data.username", `{"data":null}`, "default"},
		{"data.username", `{"data":{"username":123}}`, "default"},
		{"data.username", `{"data":{"username":""}}`, "default"},
		{"data.username", `{"email":"wrong@example.com"}`, "default"},
	} {
		t.Run(tc.body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, tc.body) }))
			defer server.Close()
			m, err := f.resolver.GetOAuth(f.ctx, "acme", contracts.CallerFrom(f.ctx).UserID)
			if err != nil {
				t.Fatal(err)
			}
			m.UserinfoEndpoint, m.UserinfoAccountPath = server.URL, tc.path
			if got := f.flow.fetchAccount(f.ctx, m, "token"); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
