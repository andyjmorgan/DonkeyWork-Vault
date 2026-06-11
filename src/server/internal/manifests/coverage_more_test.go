package manifests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/store"
	"donkeywork.dev/vault-server/internal/store/memstore"
)

func TestErrInvalidSlugError(t *testing.T) {
	e := ErrInvalidSlug{Slug: "bad slug"}
	if e.Error() == "" {
		t.Fatal("expected message")
	}
}

func TestLoadFromFSErrors(t *testing.T) {
	const id1 = "11111111-1111-1111-1111-111111111111"

	t.Run("invalid yaml", func(t *testing.T) {
		fsys := fstest.MapFS{"oauth/bad.yaml": {Data: []byte("key: [unterminated")}}
		if _, err := loadFromFS(fsys, "oauth"); err == nil {
			t.Fatal("expected yaml error")
		}
	})

	t.Run("missing key or token endpoint", func(t *testing.T) {
		fsys := fstest.MapFS{"oauth/x.yaml": {Data: []byte("name: X\n")}}
		if _, err := loadFromFS(fsys, "oauth"); err == nil {
			t.Fatal("expected missing key/token error")
		}
	})

	t.Run("missing id", func(t *testing.T) {
		fsys := fstest.MapFS{"oauth/x.yaml": {Data: []byte("key: x\ntoken_endpoint: t\n")}}
		if _, err := loadFromFS(fsys, "oauth"); err == nil {
			t.Fatal("expected missing id error")
		}
	})

	t.Run("duplicate id", func(t *testing.T) {
		doc := "id: " + id1 + "\nkey: a\ntoken_endpoint: t\n"
		doc2 := "id: " + id1 + "\nkey: b\ntoken_endpoint: t\n"
		fsys := fstest.MapFS{
			"oauth/a.yaml": {Data: []byte(doc)},
			"oauth/b.yaml": {Data: []byte(doc2)},
		}
		if _, err := loadFromFS(fsys, "oauth"); err == nil {
			t.Fatal("expected duplicate id error")
		}
	})

	t.Run("default scope delimiter applied", func(t *testing.T) {
		doc := "id: " + id1 + "\nkey: a\ntoken_endpoint: t\n" // no scope_delimiter
		fsys := fstest.MapFS{"oauth/a.yaml": {Data: []byte(doc)}}
		l, err := loadFromFS(fsys, "oauth")
		if err != nil {
			t.Fatal(err)
		}
		all := l.All()
		if len(all) != 1 || all[0].ScopeDelimiter != " " {
			t.Fatalf("expected default delimiter, got %+v", all)
		}
	})

	t.Run("missing root directory", func(t *testing.T) {
		// WalkDir surfaces the lstat error on a non-existent root.
		if _, err := loadFromFS(fstest.MapFS{}, "nope"); err == nil {
			t.Fatal("expected walk error for missing root")
		}
	})
}

func TestDiscoveryErrorPaths(t *testing.T) {
	t.Run("bad request url", func(t *testing.T) {
		d := NewDiscovery(http.DefaultClient)
		// A control character makes http.NewRequestWithContext fail before any dial.
		if _, err := d.Discover(context.Background(), "http://exa\x7fmple/.well-known/x"); err == nil {
			t.Fatal("expected request build error")
		}
	})

	t.Run("non-2xx status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		if _, err := NewDiscovery(srv.Client()).Discover(context.Background(), srv.URL); err == nil {
			t.Fatal("expected HTTP status error")
		}
	})

	t.Run("invalid json body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
		defer srv.Close()
		if _, err := NewDiscovery(srv.Client()).Discover(context.Background(), srv.URL); err == nil {
			t.Fatal("expected json decode error")
		}
	})

	t.Run("empty scope skipped", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"issuer":"https://idp.example","token_endpoint":"t","scopes_supported":["","openid"]}`))
		}))
		defer srv.Close()
		m, err := NewDiscovery(srv.Client()).Discover(context.Background(), srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		// Only the non-empty "openid" scope is recorded.
		if len(m.Scopes) != 1 || m.Scopes[0].Value != "openid" {
			t.Fatalf("scopes = %+v", m.Scopes)
		}
	})
}

func callerCtx(t *testing.T) (context.Context, uuid.UUID) {
	t.Helper()
	u := uuid.New()
	return contracts.WithCaller(context.Background(), contracts.Caller{UserID: u, TenantID: uuid.New()}), u
}

func TestResolverStoreErrors(t *testing.T) {
	l, _ := NewLoader()

	t.Run("ListOAuth store error", func(t *testing.T) {
		ms := memstore.New()
		ms.FailNext = errors.New("list failed")
		r := NewResolver(ms, l)
		ctx, _ := callerCtx(t)
		if _, err := r.ListOAuth(ctx); err == nil {
			t.Fatal("expected list error")
		}
	})

	t.Run("ResolveProviderID store error", func(t *testing.T) {
		ms := memstore.New()
		ms.FailNext = errors.New("get failed")
		r := NewResolver(ms, l)
		ctx, u := callerCtx(t)
		if _, err := r.ResolveProviderID(ctx, "acme", u); err == nil {
			t.Fatal("expected resolve error")
		}
	})

	t.Run("UpsertOAuth get error", func(t *testing.T) {
		ms := memstore.New()
		ms.FailNext = errors.New("get failed")
		r := NewResolver(ms, l)
		ctx, _ := callerCtx(t)
		if err := r.UpsertOAuth(ctx, Manifest{Key: "acme", TokenEndpoint: "t"}); err == nil {
			t.Fatal("expected upsert get error")
		}
	})
}

// TestListOAuthSortAndMaterializeError covers the sort comparator (two differing keys) and the
// materialize error branch (a row with malformed DocumentJSON) inside ListOAuth.
func TestListOAuthSortAndMaterializeError(t *testing.T) {
	ms := memstore.New()
	l, _ := NewLoader()
	r := NewResolver(ms, l)
	ctx, u := callerCtx(t)

	// Two valid rows with differing keys so the sort.Slice comparator executes.
	if err := r.UpsertOAuth(ctx, Manifest{Key: "bbb", TokenEndpoint: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := r.UpsertOAuth(ctx, Manifest{Key: "aaa", TokenEndpoint: "t"}); err != nil {
		t.Fatal(err)
	}
	list, err := r.ListOAuth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Key != "aaa" || list[1].Key != "bbb" {
		t.Fatalf("expected sorted [aaa,bbb], got %+v", list)
	}

	// Now inject a row with broken JSON so materialize fails.
	_ = ms.InsertManifest(ctx, &store.ProviderManifest{
		UserID:       u,
		Kind:         "oauth",
		Key:          "broken",
		ProviderID:   uuid.New(),
		DocumentJSON: "{not-json",
	})
	if _, err := r.ListOAuth(ctx); err == nil {
		t.Fatal("expected materialize error from broken row")
	}
}

// TestUpsertEditPreservesParentID covers the row.ParentID != Nil branch on edit.
func TestUpsertEditPreservesParentID(t *testing.T) {
	ms := memstore.New()
	l, _ := NewLoader()
	r := NewResolver(ms, l)
	ctx, _ := callerCtx(t)

	parent := uuid.New()
	if err := r.UpsertOAuth(ctx, Manifest{Key: "acme", TokenEndpoint: "t", ParentID: parent}); err != nil {
		t.Fatal(err)
	}
	// Edit without supplying ParentID — the stored parent breadcrumb must be preserved.
	if err := r.UpsertOAuth(ctx, Manifest{Key: "acme", TokenEndpoint: "t2"}); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetOAuth(ctx, "acme", contracts.CallerFrom(ctx).UserID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ParentID != parent {
		t.Fatalf("parent id = %s, want %s", got.ParentID, parent)
	}
}
