package main

import (
	"context"
	"fmt"
	"net/http"

	"donkeywork.dev/vault-cli/internal/credstore"
	"donkeywork.dev/vault-cli/internal/vaultapi"
)

// newClient builds a vaultapi client for the resolved base URL, injecting the
// caller's API key as the X-Api-Key header on every request.
//
// The base URL and transport (plaintext vs TLS) come from httpBaseURL(), where the
// --addr scheme is the sole signal (https:// ⇒ TLS; a bare host defaults to http://).
// The key is resolved via credstore: --api-key / VAULT_API_KEY, then the OS keyring,
// then the 0600 file written by `dwvault auth login`.
func newClient() (*vaultapi.ClientWithResponses, error) {
	base := httpBaseURL()

	effKey := apiKey
	if effKey == "" {
		k, _, err := credstore.Resolve(base)
		if err != nil {
			return nil, fmt.Errorf("no credentials for %s; run `dwvault auth login` or set VAULT_API_KEY", base)
		}
		effKey = k
	}

	editor := func(_ context.Context, req *http.Request) error {
		req.Header.Set("X-Api-Key", effKey)
		req.Header.Set("Accept", "application/json")
		return nil
	}
	return vaultapi.NewClientWithResponses(base, vaultapi.WithRequestEditorFn(editor))
}

// deref returns the pointed-to string, or "" when the pointer is nil.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
