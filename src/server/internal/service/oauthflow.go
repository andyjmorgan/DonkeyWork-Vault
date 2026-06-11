package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/crypto"
	"donkeywork.dev/vault-server/internal/manifests"
	"donkeywork.dev/vault-server/internal/oauth"
	"donkeywork.dev/vault-server/internal/store"
)

// BeginAuthResult is the authorize URL plus the anti-forgery state for a started flow.
type BeginAuthResult struct {
	AuthorizeURL string
	State        string
}

// CompleteAuthResult summarises a completed flow.
type CompleteAuthResult struct {
	Provider  string
	Account   string
	Scopes    []string
	ExpiresAt *time.Time
}

// OAuthFlowService drives the authorization-code + PKCE flow and stores the resulting tokens.
type OAuthFlowService struct {
	store    store.Store
	cipher   crypto.Cipher
	resolver *manifests.Resolver
	audit    *audit.Log
	client   *http.Client
	logger   *slog.Logger
}

// NewOAuthFlowService builds the service.
func NewOAuthFlowService(s store.Store, c crypto.Cipher, r *manifests.Resolver, a *audit.Log, client *http.Client, logger *slog.Logger) *OAuthFlowService {
	if client == nil {
		client = http.DefaultClient
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &OAuthFlowService{store: s, cipher: c, resolver: r, audit: a, client: client, logger: logger}
}

// Begin starts a flow: it persists a one-time PKCE/state row and returns the provider authorize URL.
func (s *OAuthFlowService) Begin(ctx context.Context, provider string, scopes []string, publicBaseURL string) (*BeginAuthResult, error) {
	ctx, span := startSpan(ctx, "oauthflow.begin")
	defer span.End()
	span.SetAttributes(attribute.String("oauth.provider", provider))

	caller := contracts.CallerFrom(ctx)
	manifest, err := s.resolver.GetOAuth(ctx, provider, caller.UserID)
	if err != nil {
		return nil, err
	}
	if manifest == nil {
		return nil, OAuthAuthorizationError{"unknown OAuth provider '" + provider + "'."}
	}
	config, err := s.store.GetOAuthConfigByProvider(ctx, caller.UserID, manifest.ID)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, OAuthAuthorizationError{"no OAuth app config for '" + provider + "'. Add client_id/secret first."}
	}

	clientID, err := s.cipher.DecryptToString(config.ClientIDCipher)
	if err != nil {
		return nil, err
	}

	scopeList := scopes
	if len(scopeList) == 0 {
		if config.ScopesJSON != nil {
			scopeList = decodeScopes(config.ScopesJSON)
		} else {
			scopeList = manifest.DefaultScopes
		}
	}
	kept, dropped := FilterScopesToCatalog(manifest, scopeList)
	if len(dropped) > 0 {
		s.logger.WarnContext(ctx, "dropped scopes not in provider catalog", "provider", provider, "dropped", strings.Join(dropped, ", "))
	}
	scopeList = kept

	verifier := oauth.GenerateVerifier()
	state := oauth.RandomState()
	redirectURI := strings.TrimRight(publicBaseURL, "/") + "/api/oauth/callback"

	if err := s.store.InsertOAuthState(ctx, &store.OAuthState{
		State: state, Provider: provider, CodeVerifier: verifier,
		OwnerUserID: caller.UserID, OwnerTenantID: caller.TenantID,
		RedirectURI: redirectURI, ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}); err != nil {
		return nil, err
	}

	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {strings.Join(scopeList, manifest.ScopeDelimiter)},
		"state":                 {state},
		"code_challenge":        {oauth.Challenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	for k, v := range manifest.AuthorizeParams {
		q.Set(k, v)
	}
	authorizeURL := manifest.AuthorizationEndpoint + "?" + q.Encode()
	return &BeginAuthResult{AuthorizeURL: authorizeURL, State: state}, nil
}

// FilterScopesToCatalog restricts requested scopes to what the provider declares (catalog ∪
// defaults), preserving request order. When the provider declares neither, the request passes
// through unfiltered.
func FilterScopesToCatalog(m *manifests.Manifest, requested []string) (kept, dropped []string) {
	allowed := make(map[string]bool)
	for _, sc := range m.Scopes {
		allowed[sc.Value] = true
	}
	for _, sc := range m.DefaultScopes {
		allowed[sc] = true
	}
	if len(allowed) == 0 {
		return requested, nil
	}
	for _, sc := range requested {
		if allowed[sc] {
			kept = append(kept, sc)
		} else {
			dropped = append(dropped, sc)
		}
	}
	return kept, dropped
}

// Complete exchanges the authorization code for tokens and stores them. Identity (provider + owner)
// comes entirely from the one-time state row, which is claimed atomically to reject replays.
func (s *OAuthFlowService) Complete(ctx context.Context, code, state string) (*CompleteAuthResult, error) {
	ctx, span := startSpan(ctx, "oauthflow.complete")
	defer span.End()

	result, err := s.completeCore(ctx, code, state)
	if err != nil {
		s.audit.Emit(ctx, audit.EmitParams{Type: audit.EventTokenAdded, Outcome: audit.OutcomeFailure,
			TargetKind: "oauth_token", Detail: err.Error()})
	}
	return result, err
}

func (s *OAuthFlowService) completeCore(ctx context.Context, code, state string) (*CompleteAuthResult, error) {
	stateRow, err := s.store.GetOAuthStateByState(ctx, state)
	if err != nil {
		return nil, err
	}
	if stateRow == nil {
		return nil, OAuthAuthorizationError{"invalid or expired state."}
	}
	provider := stateRow.Provider
	if stateRow.ExpiresAt.Before(time.Now().UTC()) {
		return nil, OAuthAuthorizationError{"invalid or expired state."}
	}

	// Atomic claim: exactly one callback may consume a state row.
	deleted, err := s.store.DeleteOAuthState(ctx, stateRow.ID)
	if err != nil {
		return nil, err
	}
	if deleted == 0 {
		return nil, OAuthAuthorizationError{"state already used."}
	}

	manifest, err := s.resolver.GetOAuth(ctx, provider, stateRow.OwnerUserID)
	if err != nil {
		return nil, err
	}
	if manifest == nil {
		return nil, OAuthAuthorizationError{"unknown OAuth provider '" + provider + "'."}
	}
	config, err := s.store.GetOAuthConfigByProvider(ctx, stateRow.OwnerUserID, manifest.ID)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, OAuthAuthorizationError{"no OAuth app config for '" + provider + "'."}
	}

	clientID, err := s.cipher.DecryptToString(config.ClientIDCipher)
	if err != nil {
		return nil, err
	}
	clientSecret, err := s.cipher.DecryptToString(config.ClientSecretCipher)
	if err != nil {
		return nil, err
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {stateRow.RedirectURI},
		"code_verifier": {stateRow.CodeVerifier},
	}
	status, body, err := postForm(ctx, s.client, manifest.TokenEndpoint, form)
	if err != nil {
		return nil, OAuthAuthorizationError{fmt.Sprintf("token exchange failed: %v", err)}
	}
	if !httpOK(status) {
		return nil, OAuthAuthorizationError{fmt.Sprintf("token exchange failed: HTTP %d", status)}
	}

	var parsed tokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.AccessToken == "" {
		return nil, OAuthAuthorizationError{"token exchange returned no access_token."}
	}

	var expiresAt *time.Time
	if parsed.ExpiresIn > 0 {
		t := time.Now().UTC().Add(time.Duration(parsed.ExpiresIn) * time.Second)
		expiresAt = &t
	}
	scopes := splitScopes(parsed.Scope)
	if len(scopes) == 0 {
		scopes = decodeScopes(config.ScopesJSON)
	}

	account := s.fetchAccount(ctx, manifest, parsed.AccessToken)

	if err := s.storeToken(ctx, stateRow, manifest.ID, provider, account, parsed, expiresAt, scopes); err != nil {
		return nil, err
	}

	s.audit.Emit(ctx, audit.EmitParams{Type: audit.EventTokenAdded, Outcome: audit.OutcomeSuccess,
		TargetKind: "oauth_token", TargetProvider: provider, TargetAccount: account,
		UserID: &stateRow.OwnerUserID, TenantID: &stateRow.OwnerTenantID})

	return &CompleteAuthResult{Provider: provider, Account: account, Scopes: scopes, ExpiresAt: expiresAt}, nil
}

func (s *OAuthFlowService) storeToken(ctx context.Context, stateRow *store.OAuthState, pid uuid.UUID, provider, account string, parsed tokenResponse, expiresAt *time.Time, scopes []string) error {
	accessBlob, err := s.cipher.EncryptString(parsed.AccessToken)
	if err != nil {
		return err
	}
	var refreshBlob []byte
	if parsed.RefreshToken != "" {
		if refreshBlob, err = s.cipher.EncryptString(parsed.RefreshToken); err != nil {
			return err
		}
	}
	scopesJSON := encodeScopes(scopes)
	now := time.Now().UTC()

	existing, err := s.store.FindOAuthToken(ctx, stateRow.OwnerUserID, pid, account)
	if err != nil {
		return err
	}
	if existing == nil {
		return s.store.InsertOAuthToken(ctx, &store.OAuthToken{
			UserID: stateRow.OwnerUserID, TenantID: stateRow.OwnerTenantID, ProviderID: pid, ProviderKey: provider,
			Account: account, AccessTokenCipher: accessBlob, RefreshTokenCipher: refreshBlob,
			ScopesJSON: &scopesJSON, ExpiresAt: expiresAt, LastRefreshedAt: &now,
		})
	}
	existing.AccessTokenCipher = accessBlob
	if parsed.RefreshToken != "" {
		existing.RefreshTokenCipher = refreshBlob
	}
	existing.ScopesJSON = &scopesJSON
	existing.ExpiresAt = expiresAt
	existing.LastRefreshedAt = &now
	return s.store.UpdateOAuthToken(ctx, existing)
}

// fetchAccount best-effort resolves the external account identifier from the userinfo endpoint.
func (s *OAuthFlowService) fetchAccount(ctx context.Context, m *manifests.Manifest, accessToken string) string {
	if m.UserinfoEndpoint == "" {
		return "default"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.UserinfoEndpoint, nil)
	if err != nil {
		return "default"
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "donkeywork-vault")
	resp, err := s.client.Do(req)
	if err != nil {
		return "default"
	}
	defer resp.Body.Close()
	if !httpOK(resp.StatusCode) {
		return "default"
	}
	var info map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "default"
	}
	for _, key := range []string{"email", "mail", "userPrincipalName", "preferred_username", "login", "sub"} {
		if v, ok := info[key].(string); ok && v != "" {
			return v
		}
	}
	return "default"
}

func splitScopes(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' })
}
