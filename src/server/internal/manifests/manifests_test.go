package manifests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/store/memstore"
)

func TestLoaderEmbedded(t *testing.T) {
	l, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	all := l.All()
	if len(all) < 5 {
		t.Fatalf("expected embedded providers, got %d", len(all))
	}
	// sorted by key
	for i := 1; i < len(all); i++ {
		if all[i-1].Key > all[i].Key {
			t.Fatal("not sorted by key")
		}
	}
	var google bool
	for _, m := range all {
		if m.Key == "google" {
			google = true
			if m.ID == uuid.Nil || m.TokenEndpoint == "" {
				t.Fatal("google manifest incomplete")
			}
		}
	}
	if !google {
		t.Fatal("google template missing")
	}
}

func TestHostHelpers(t *testing.T) {
	if NormalizeHost("WWW.Dropbox.com.") != "dropbox.com" {
		t.Fatal("normalize")
	}
	if KeyFromHost("accounts.google.com") != "google" {
		t.Fatal("key from host google")
	}
	if KeyFromHost("dropbox") != "dropbox" {
		t.Fatal("single label")
	}
	if KeyFromHost("") != "" {
		t.Fatal("empty host")
	}
}

func TestDiscovery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"issuer":"https://www.idp.com","authorization_endpoint":"a","token_endpoint":"t","userinfo_endpoint":"u","scopes_supported":["openid","email","weird"]}`))
	}))
	defer srv.Close()

	d := NewDiscovery(srv.Client())
	m, err := d.Discover(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if m.Key != "idp" || m.TokenEndpoint != "t" {
		t.Fatalf("mapping: %+v", m)
	}
	if len(m.DefaultScopes) != 2 { // openid, email
		t.Fatalf("default scopes %v", m.DefaultScopes)
	}

	// already has /.well-known/ in url
	if _, err := d.Discover(context.Background(), srv.URL+"/.well-known/openid-configuration"); err != nil {
		t.Fatal(err)
	}
	// unreachable
	if _, err := d.Discover(context.Background(), "http://127.0.0.1:1/x"); err == nil {
		t.Fatal("expected error")
	}
	// nil client falls back to default
	_ = NewDiscovery(nil)
}

func TestResolverLifecycle(t *testing.T) {
	ms := memstore.New()
	l, _ := NewLoader()
	r := NewResolver(ms, l)
	u := uuid.New()
	ctx := contracts.WithCaller(context.Background(), contracts.Caller{UserID: u, TenantID: uuid.New()})

	if len(r.ListTemplates()) < 5 {
		t.Fatal("templates")
	}

	// invalid slug
	if err := r.UpsertOAuth(ctx, Manifest{Key: "bad slug"}); err == nil {
		t.Fatal("expected slug error")
	}

	// add
	if err := r.UpsertOAuth(ctx, Manifest{Key: "acme", TokenEndpoint: "t", DefaultScopes: []string{"openid"}}); err != nil {
		t.Fatal(err)
	}
	pid, _ := r.ResolveProviderID(ctx, "acme", u)
	if pid == uuid.Nil {
		t.Fatal("provider id")
	}
	// edit keeps provider id
	if err := r.UpsertOAuth(ctx, Manifest{Key: "acme", TokenEndpoint: "t2"}); err != nil {
		t.Fatal(err)
	}
	pid2, _ := r.ResolveProviderID(ctx, "acme", u)
	if pid2 != pid {
		t.Fatal("provider id changed on edit")
	}
	got, _ := r.GetOAuth(ctx, "acme", u)
	if got == nil || got.TokenEndpoint != "t2" {
		t.Fatalf("get: %+v", got)
	}
	if list, _ := r.ListOAuth(ctx); len(list) != 1 {
		t.Fatal("list")
	}
	// unknown
	if got, _ := r.GetOAuth(ctx, "ghost", u); got != nil {
		t.Fatal("ghost should be nil")
	}
	// delete
	if ok, _ := r.Delete(ctx, "oauth", "acme"); !ok {
		t.Fatal("delete")
	}
}
