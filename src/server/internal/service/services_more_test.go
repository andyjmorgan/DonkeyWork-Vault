package service

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/store/memstore"
)

func callerCtx() context.Context {
	return contracts.WithCaller(context.Background(), contracts.Caller{UserID: uuid.New(), TenantID: uuid.New()})
}

func TestAPIKeyEditAndBasic(t *testing.T) {
	ms := memstore.New()
	svc := NewAPIKeyService(ms, testCipher(t), audit.NewLog(10, nil, nil))
	ctx := callerCtx()

	// create
	if _, err := svc.Create(ctx, CreateAPIKeyParams{Name: "k", Secret: strPtr("s1"), Header: strPtr("X-Key"), Prefix: strPtr("p-")}); err != nil {
		t.Fatal(err)
	}
	// edit (same name, blank secret keeps existing)
	if _, err := svc.Create(ctx, CreateAPIKeyParams{Name: "k", Description: strPtr("updated")}); err != nil {
		t.Fatal(err)
	}
	sec, err := svc.GetByName(ctx, "k")
	if err != nil || sec.Secret != "s1" || deref(sec.Description) != "updated" {
		t.Fatalf("edit keep secret: %+v %v", sec, err)
	}

	// http_basic: username set defaults header to Authorization
	if _, err := svc.Create(ctx, CreateAPIKeyParams{Name: "b", Secret: strPtr("pw"), Username: strPtr("user"), Kind: contracts.KindHTTPBasic}); err != nil {
		t.Fatal(err)
	}
	bsec, _ := svc.GetByName(ctx, "b")
	if deref(bsec.Header) != "Authorization" || deref(bsec.Username) != "user" {
		t.Fatalf("basic: %+v", bsec)
	}

	// ssh: a username-bearing login that is NOT Basic must not get an Authorization header stamped.
	if _, err := svc.Create(ctx, CreateAPIKeyParams{Name: "s", Secret: strPtr("key"), Username: strPtr("root"), Kind: contracts.KindSSH}); err != nil {
		t.Fatal(err)
	}
	ssec, _ := svc.GetByName(ctx, "s")
	if ssec.Header != nil || deref(ssec.Username) != "root" || ssec.Kind != contracts.KindSSH {
		t.Fatalf("ssh: %+v", ssec)
	}

	// username-bearing credential without a secret on create -> error
	if _, err := svc.Create(ctx, CreateAPIKeyParams{Name: "c", Username: strPtr("user"), Kind: contracts.KindHTTPBasic}); err == nil {
		t.Fatal("expected password required")
	}

	// reveal missing
	if got, _ := svc.GetByName(ctx, "missing"); got != nil {
		t.Fatal("missing reveal should be nil")
	}
	// list + delete (k, b, s created; c failed validation)
	list, _ := svc.List(ctx)
	if len(list) != 3 {
		t.Fatalf("list %d", len(list))
	}
	if ok, _ := svc.Delete(ctx, list[0].ID); !ok {
		t.Fatal("delete")
	}
}

func TestAccessKeyAuthenticate(t *testing.T) {
	ms := memstore.New()
	svc := NewAccessKeyService(ms, audit.NewLog(10, nil, nil))
	ctx := callerCtx()

	key, secret, err := svc.Create(ctx, "ci", strPtr("desc"), []string{"vault:read", "vault:read"}) // dup collapses
	if err != nil {
		t.Fatal(err)
	}
	// authenticate ok
	p, err := svc.Authenticate(ctx, secret)
	if err != nil || p == nil || p.Name != "ci" {
		t.Fatalf("auth: %+v %v", p, err)
	}
	// empty + unknown secret -> nil
	if p, _ := svc.Authenticate(ctx, ""); p != nil {
		t.Fatal("empty")
	}
	if p, _ := svc.Authenticate(ctx, "dwv_unknown"); p != nil {
		t.Fatal("unknown")
	}
	// disable then authenticate -> nil
	if _, err := svc.SetEnabled(ctx, key.ID, false); err != nil {
		t.Fatal(err)
	}
	if p, _ := svc.Authenticate(ctx, secret); p != nil {
		t.Fatal("disabled key should not authenticate")
	}
	// validation
	if _, _, err := svc.Create(ctx, "", nil, []string{"vault:read"}); err == nil {
		t.Fatal("name required")
	}
	if _, _, err := svc.Create(ctx, "x", nil, nil); err == nil {
		t.Fatal("scope required")
	}
	// set enabled / delete missing
	if got, _ := svc.SetEnabled(ctx, uuid.New(), true); got != nil {
		t.Fatal("missing set enabled")
	}
	if ok, _ := svc.Delete(ctx, uuid.New()); ok {
		t.Fatal("missing delete")
	}
}

func TestOAuthConfigEditAndMask(t *testing.T) {
	f := newOAuthFixture(t) // seeds acme manifest + config
	// edit existing config (blank secret keeps it)
	id, err := f.configs.Upsert(f.ctx, "acme", "new-client-id", nil, []string{"openid"}, strPtr("https://r"))
	if err != nil {
		t.Fatal(err)
	}
	if id == uuid.Nil {
		t.Fatal("edit id")
	}
	list, _ := f.configs.List(f.ctx)
	if len(list) != 1 || list[0].ClientIDMasked == "" {
		t.Fatalf("list/mask: %+v", list)
	}
	// short client id masks to ***
	if mask("short") != "***" {
		t.Fatal("short mask")
	}
	// delete
	if ok, _ := f.configs.Delete(f.ctx, id); !ok {
		t.Fatal("delete config")
	}
}
