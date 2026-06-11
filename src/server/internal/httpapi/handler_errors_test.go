package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestHandlerStoreErrors drives every handler's store-error branch (HTTP 500) by forcing the
// in-memory store to fail. The JWT harness is used so authentication never touches the store and the
// forced failure lands in the handler.
func TestHandlerStoreErrors(t *testing.T) {
	h := newJWTHarness(t, "web", "cli")
	webTok := func() string {
		return makeJWT(t, map[string]any{"iss": testIssuer, "sub": uuid.NewString(), "aud": []string{"web"}, "azp": "web", "exp": time.Now().Add(time.Hour).Unix()})
	}

	type call struct {
		name, method, path string
		body               any
	}
	calls := []call{
		{"list api keys", "GET", "/api/v1/api-keys", nil},
		{"create api key", "POST", "/api/v1/api-keys", createAPIKeyRequest{Name: "n", Secret: ptr("s")}},
		{"reveal api key", "GET", "/api/v1/api-keys/n/reveal", nil},
		{"credential shape", "GET", "/api/v1/credentials/n", nil},
		{"list access keys", "GET", "/api/v1/access-keys", nil},
		{"create access key", "POST", "/api/v1/access-keys", createAccessKeyRequest{Name: "n", Scopes: []string{"vault:read"}}},
		{"list manifests", "GET", "/api/v1/manifests", nil},
		{"upsert manifest", "POST", "/api/v1/manifests/oauth", upsertOAuthManifestRequest{Key: "acme", TokenEndpoint: ptr("t")}},
		{"delete manifest", "DELETE", "/api/v1/manifests/oauth/acme", nil},
		{"list configs", "GET", "/api/v1/oauth/configs", nil},
		{"upsert config", "POST", "/api/v1/oauth/configs", upsertOAuthConfigRequest{Provider: "acme", ClientID: "c", ClientSecret: ptr("s")}},
		{"list tokens", "GET", "/api/v1/oauth/tokens", nil},
		{"get token", "GET", "/api/v1/oauth/acme/token", nil},
		{"connect", "GET", "/api/v1/oauth/acme/connect", nil},
		{"audit", "GET", "/api/v1/audit", nil},
	}

	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			h.ms.FailNext = errors.New("db down")
			var rdr *bytes.Reader
			if c.body != nil {
				b, _ := json.Marshal(c.body)
				rdr = bytes.NewReader(b)
			} else {
				rdr = bytes.NewReader(nil)
			}
			req := httptest.NewRequest(c.method, c.path, rdr)
			req.Header.Set("Authorization", "Bearer "+webTok())
			rec := httptest.NewRecorder()
			h.h.ServeHTTP(rec, req)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("%s: expected 500, got %d body=%s", c.name, rec.Code, rec.Body)
			}
			h.ms.FailNext = nil // reset in case the handler did not consume it
		})
	}
}
