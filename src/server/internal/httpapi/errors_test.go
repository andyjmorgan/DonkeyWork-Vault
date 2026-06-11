package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/service"
	"donkeywork.dev/vault-server/internal/store"
)

func TestWriteServiceErrorMapping(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{nil, 0},
		{service.ValidationError{Message: "bad"}, http.StatusBadRequest},
		{service.OAuthAuthorizationError{Message: "x"}, http.StatusBadRequest},
		{service.OAuthRefreshError{Message: "y"}, http.StatusBadGateway},
		{errors.New("boom"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		handled := writeServiceError(rec, c.err)
		if c.err == nil {
			if handled {
				t.Fatal("nil should not be handled")
			}
			continue
		}
		if !handled || rec.Code != c.want {
			t.Fatalf("err %v -> code %d want %d", c.err, rec.Code, c.want)
		}
	}
}

func TestBadUUIDParams(t *testing.T) {
	h := newHarness(t)
	paths := []struct{ method, path string }{
		{"DELETE", "/api/v1/api-keys/not-a-uuid"},
		{"DELETE", "/api/v1/access-keys/not-a-uuid"},
		{"PATCH", "/api/v1/access-keys/not-a-uuid"},
		{"DELETE", "/api/v1/oauth/configs/not-a-uuid"},
		{"DELETE", "/api/v1/oauth/tokens/not-a-uuid"},
	}
	for _, p := range paths {
		rec := h.do(t, p.method, p.path, setEnabledRequest{Enabled: true}, true)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s %s -> %d, want 400", p.method, p.path, rec.Code)
		}
	}
}

func TestDeleteTokenHandler(t *testing.T) {
	h := newHarness(t)
	id := uuid.New()
	live, _ := h.cipher.EncryptString("x")
	_ = h.ms.InsertOAuthToken(context.Background(), &store.OAuthToken{
		ID: id, UserID: h.userID, ProviderID: uuid.New(), ProviderKey: "acme", Account: "a",
		AccessTokenCipher: live, RefreshTokenCipher: []byte{1},
	})
	if rec := h.do(t, "DELETE", "/api/v1/oauth/tokens/"+id.String(), nil, true); rec.Code != 204 {
		t.Fatalf("delete token %d", rec.Code)
	}
	if rec := h.do(t, "DELETE", "/api/v1/oauth/tokens/"+uuid.New().String(), nil, true); rec.Code != 404 {
		t.Fatalf("delete missing token %d", rec.Code)
	}
}

func TestStoreErrorReturns500(t *testing.T) {
	// Use the JWT harness so authentication does not touch the store; the forced failure then lands
	// in the handler's store call rather than in access-key auth.
	h := newJWTHarness(t, "web", "cli")
	tok := makeJWT(t, map[string]any{"iss": testIssuer, "sub": uuid.NewString(), "aud": []string{"web"}, "azp": "web", "exp": timeFuture().Unix()})
	h.ms.FailNext = errors.New("db down")
	if rec := bearer(h, t, "GET", "/api/v1/api-keys", tok); rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestAuditTimeFilters(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "GET", "/api/v1/audit?limit=5&offset=0&since=2020-01-01T00:00:00Z&until=2999-01-01T00:00:00Z&userId="+h.userID.String(), nil, true)
	if rec.Code != 200 {
		t.Fatalf("audit time filters %d body=%s", rec.Code, rec.Body)
	}
}

func TestParseTimeHelper(t *testing.T) {
	if parseTime("") != nil {
		t.Fatal("empty")
	}
	if parseTime("garbage") != nil {
		t.Fatal("garbage")
	}
	if parseTime("2020-01-02T03:04:05Z") == nil {
		t.Fatal("valid")
	}
}
