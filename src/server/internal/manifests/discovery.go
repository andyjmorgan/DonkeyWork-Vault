package manifests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Discovery fetches an OIDC `.well-known/openid-configuration` and maps it to a draft manifest.
type Discovery struct {
	client *http.Client
}

// NewDiscovery builds a discovery service over the given client (which should carry the otelhttp
// transport in production so outbound calls are traced).
func NewDiscovery(client *http.Client) *Discovery {
	if client == nil {
		client = http.DefaultClient
	}
	return &Discovery{client: client}
}

type wellKnown struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// Discover fetches and maps the OIDC discovery document at url.
func (d *Discovery) Discover(ctx context.Context, raw string) (*Manifest, error) {
	u := strings.TrimSpace(raw)
	if !strings.Contains(strings.ToLower(u), "/.well-known/") {
		u = strings.TrimRight(u, "/") + "/.well-known/openid-configuration"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "donkeywork-vault")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("discovery HTTP %d", resp.StatusCode)
	}

	var wk wellKnown
	if err := json.NewDecoder(resp.Body).Decode(&wk); err != nil {
		return nil, err
	}

	m := &Manifest{
		AuthorizationEndpoint: wk.AuthorizationEndpoint,
		TokenEndpoint:         wk.TokenEndpoint,
		UserinfoEndpoint:      wk.UserinfoEndpoint,
		ScopeDelimiter:        " ",
		AuthorizeParams:       map[string]string{},
	}
	if iu, err := url.Parse(wk.Issuer); err == nil && iu.Host != "" {
		m.Name = NormalizeHost(iu.Host)
		m.Key = KeyFromHost(iu.Host)
	}
	for _, s := range wk.ScopesSupported {
		if s == "" {
			continue
		}
		m.Scopes = append(m.Scopes, ScopeDef{Value: s, Category: "discovered"})
		switch s {
		case "openid", "email", "profile", "offline_access":
			m.DefaultScopes = append(m.DefaultScopes, s)
		}
	}
	return m, nil
}

// NormalizeHost lower-cases a host and strips a leading www.
func NormalizeHost(host string) string {
	h := strings.ToLower(strings.TrimRight(strings.TrimSpace(host), "."))
	return strings.TrimPrefix(h, "www.")
}

// KeyFromHost derives a short provider key from an issuer host (the registrable label).
func KeyFromHost(host string) string {
	labels := strings.FieldsFunc(NormalizeHost(host), func(r rune) bool { return r == '.' })
	switch len(labels) {
	case 0:
		return ""
	case 1:
		return labels[0]
	default:
		return labels[len(labels)-2]
	}
}
