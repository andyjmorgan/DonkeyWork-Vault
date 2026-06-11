package service

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/manifests"
	"donkeywork.dev/vault-server/internal/store"
	"donkeywork.dev/vault-server/internal/store/memstore"
)

// failCipher fails encrypt and/or decrypt to exercise the services' crypto-error branches.
type failCipher struct {
	encFail, decFail bool
}

func (c failCipher) Encrypt(b []byte) ([]byte, error) {
	if c.encFail {
		return nil, errors.New("enc fail")
	}
	return append([]byte("ct:"), b...), nil
}
func (c failCipher) Decrypt(b []byte) ([]byte, error) {
	if c.decFail {
		return nil, errors.New("dec fail")
	}
	return b, nil
}
func (c failCipher) EncryptString(s string) ([]byte, error) { return c.Encrypt([]byte(s)) }
func (c failCipher) DecryptToString(b []byte) (string, error) {
	d, err := c.Decrypt(b)
	return string(d), err
}

func TestAPIKeyCipherErrors(t *testing.T) {
	ms := memstore.New()
	ctx := callerCtx()
	// encrypt fails on create
	svc := NewAPIKeyService(ms, failCipher{encFail: true}, audit.NewLog(10, nil, nil))
	if _, err := svc.Create(ctx, CreateAPIKeyParams{Name: "k", Secret: strPtr("s")}); err == nil {
		t.Fatal("expected encrypt error")
	}
	// seed via a working cipher, then decrypt fails on reveal
	ok := NewAPIKeyService(ms, failCipher{}, audit.NewLog(10, nil, nil))
	if _, err := ok.Create(ctx, CreateAPIKeyParams{Name: "k2", Secret: strPtr("s")}); err != nil {
		t.Fatal(err)
	}
	bad := NewAPIKeyService(ms, failCipher{decFail: true}, audit.NewLog(10, nil, nil))
	if _, err := bad.GetByName(ctx, "k2"); err == nil {
		t.Fatal("expected decrypt error")
	}
}

func TestOAuthConfigCipherErrors(t *testing.T) {
	ms := memstore.New()
	loader, _ := manifests.NewLoader()
	resolver := manifests.NewResolver(ms, loader)
	ctx := callerCtx()
	caller := contracts.CallerFrom(ctx)
	// seed a provider so Upsert gets past ResolveProviderID
	_ = resolver.UpsertOAuth(ctx, manifests.Manifest{Key: "acme", TokenEndpoint: "t"})

	enc := NewOAuthConfigService(ms, failCipher{encFail: true}, audit.NewLog(10, nil, nil), resolver)
	if _, err := enc.Upsert(ctx, "acme", "cid", strPtr("sec"), nil, nil); err == nil {
		t.Fatal("expected encrypt error")
	}
	// seed a config row directly, then List decrypt fails
	pid, _ := resolver.ResolveProviderID(ctx, "acme", caller.UserID)
	_ = ms.InsertOAuthConfig(ctx, &store.OAuthProviderConfig{UserID: caller.UserID, ProviderID: pid, ProviderKey: "acme", ClientIDCipher: []byte{1}, ClientSecretCipher: []byte{1}})
	dec := NewOAuthConfigService(ms, failCipher{decFail: true}, audit.NewLog(10, nil, nil), resolver)
	if _, err := dec.List(ctx); err == nil {
		t.Fatal("expected decrypt error on list")
	}
}

func TestOAuthTokenDecryptError(t *testing.T) {
	ms := memstore.New()
	loader, _ := manifests.NewLoader()
	resolver := manifests.NewResolver(ms, loader)
	ctx := callerCtx()
	caller := contracts.CallerFrom(ctx)
	_ = resolver.UpsertOAuth(ctx, manifests.Manifest{Key: "acme", TokenEndpoint: "t"})
	pid, _ := resolver.ResolveProviderID(ctx, "acme", caller.UserID)
	future := time.Now().Add(time.Hour)
	_ = ms.InsertOAuthToken(ctx, &store.OAuthToken{UserID: caller.UserID, ProviderID: pid, ProviderKey: "acme", Account: "a", AccessTokenCipher: []byte{1}, RefreshTokenCipher: []byte{1}, ExpiresAt: &future})

	svc := NewOAuthTokenService(ms, failCipher{decFail: true}, audit.NewLog(10, nil, nil), resolver, nil)
	if _, err := svc.GetAccessToken(ctx, "acme", ""); err == nil {
		t.Fatal("expected decrypt error")
	}
	_ = uuid.New
}
