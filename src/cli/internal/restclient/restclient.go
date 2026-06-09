// Package restclient is a minimal HTTP client for the vault REST API. It currently
// covers GET /api/v1/me, which doubles as API-key validation for `dwvault auth`.
package restclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Me is the identity behind a credential, from GET /api/v1/me.
type Me struct {
	UserID   string `json:"userId"`
	TenantID string `json:"tenantId"`
	Email    string `json:"email"`
	Name     string `json:"name"`
}

// FetchMe validates an API key against baseURL and returns the caller identity.
// A non-2xx response is an error, so it doubles as key validation.
func FetchMe(baseURL, apiKey string) (*Me, error) {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/me"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("key rejected by %s (%s)", u, resp.Status)
	case resp.StatusCode/100 != 2:
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}

	var m Me
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("parse /me response: %w", err)
	}
	return &m, nil
}
