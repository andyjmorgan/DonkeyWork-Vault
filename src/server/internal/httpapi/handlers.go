package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/manifests"
	"donkeywork.dev/vault-server/internal/service"
)

func (s *Server) handleConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.appConfig)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	caller := contracts.CallerFrom(r.Context())
	id := caller.UserID.String()
	tenant := ""
	if caller.TenantID != uuid.Nil {
		tenant = caller.TenantID.String()
	}
	ident := identityFrom(r.Context())
	writeJSON(w, http.StatusOK, meResponse{UserID: &id, TenantID: tenant, Email: ident.Email, Name: ident.Name})
}

// ---- api keys ----

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	items, err := s.deps.APIKeys.List(r.Context())
	if writeServiceError(w, err) {
		return
	}
	out := make([]apiKeyDTO, len(items))
	for i, k := range items {
		out[i] = toAPIKeyDTO(k)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var dto createAPIKeyRequest
	if err := decodeJSON(r, &dto); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body.")
		return
	}
	item, err := s.deps.APIKeys.Create(r.Context(), service.CreateAPIKeyParams{
		Name: dto.Name, Secret: dto.Secret, Description: dto.Description, BaseURL: dto.BaseURL,
		DocsURL: dto.DocsURL, Header: dto.Header, Prefix: dto.Prefix, Username: dto.Username, Kind: dto.Kind,
	})
	if writeServiceError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, createdAPIKeyResponse{ID: item.ID, Name: item.Name})
}

func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	id, ok := uuidParam(chi.URLParam(r, "id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id.")
		return
	}
	deleted, err := s.deps.APIKeys.Delete(r.Context(), id)
	if writeServiceError(w, err) {
		return
	}
	noContentOrNotFound(w, deleted)
}

func (s *Server) handleRevealAPIKey(w http.ResponseWriter, r *http.Request) {
	secret, err := s.deps.APIKeys.GetByName(r.Context(), chi.URLParam(r, "name"))
	if writeServiceError(w, err) {
		return
	}
	if secret == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	header, value := service.AssembleHeader(secret.Kind, derefOr(secret.Header, ""), derefOr(secret.Prefix, ""), derefOr(secret.Username, ""), secret.Secret)
	writeJSON(w, http.StatusOK, revealAPIKeyResponse{
		Secret: secret.Secret, Header: header, HeaderValue: value, Prefix: derefOr(secret.Prefix, ""),
		BaseURL: derefOr(secret.BaseURL, ""), DocsURL: derefOr(secret.DocsURL, ""), Description: derefOr(secret.Description, ""),
		Scheme: service.Scheme(secret.Kind), Username: derefOr(secret.Username, ""), Kind: secret.Kind,
	})
}

func (s *Server) handleCredentialShape(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	items, err := s.deps.APIKeys.List(r.Context())
	if writeServiceError(w, err) {
		return
	}
	for _, k := range items {
		if k.Name == name {
			writeJSON(w, http.StatusOK, credentialShapeResponse{
				Header: service.HeaderName(derefOr(k.Header, "")), Prefix: derefOr(k.Prefix, ""),
				BaseURL: derefOr(k.BaseURL, ""), DocsURL: derefOr(k.DocsURL, ""), Description: derefOr(k.Description, ""),
				Scheme: service.Scheme(k.Kind), Username: derefOr(k.Username, ""), Kind: k.Kind,
			})
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

// ---- access keys ----

func (s *Server) handleListAccessKeys(w http.ResponseWriter, r *http.Request) {
	items, err := s.deps.AccessKeys.List(r.Context())
	if writeServiceError(w, err) {
		return
	}
	out := make([]accessKeyDTO, len(items))
	for i, k := range items {
		out[i] = toAccessKeyDTO(k)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateAccessKey(w http.ResponseWriter, r *http.Request) {
	var dto createAccessKeyRequest
	if err := decodeJSON(r, &dto); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body.")
		return
	}
	key, secret, err := s.deps.AccessKeys.Create(r.Context(), dto.Name, dto.Description, dto.Scopes)
	if writeServiceError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, createdAccessKeyResponse{ID: key.ID, Name: key.Name, Scopes: orEmpty(key.Scopes), Secret: secret})
}

func (s *Server) handleSetAccessKeyEnabled(w http.ResponseWriter, r *http.Request) {
	id, ok := uuidParam(chi.URLParam(r, "id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id.")
		return
	}
	var dto setEnabledRequest
	if err := decodeJSON(r, &dto); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body.")
		return
	}
	item, err := s.deps.AccessKeys.SetEnabled(r.Context(), id, dto.Enabled)
	if writeServiceError(w, err) {
		return
	}
	if item == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, accessKeyEnabledResponse{ID: item.ID, Enabled: item.Enabled})
}

func (s *Server) handleDeleteAccessKey(w http.ResponseWriter, r *http.Request) {
	id, ok := uuidParam(chi.URLParam(r, "id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id.")
		return
	}
	deleted, err := s.deps.AccessKeys.Delete(r.Context(), id)
	if writeServiceError(w, err) {
		return
	}
	noContentOrNotFound(w, deleted)
}

// ---- manifests ----

func (s *Server) handleListManifests(w http.ResponseWriter, r *http.Request) {
	items, err := s.deps.Resolver.ListOAuth(r.Context())
	if writeServiceError(w, err) {
		return
	}
	out := make([]oauthManifestDTO, len(items))
	for i, m := range items {
		out[i] = toManifestDTO(m, false)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	items := s.deps.Resolver.ListTemplates()
	out := make([]oauthManifestDTO, len(items))
	for i, m := range items {
		out[i] = toManifestDTO(m, true)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleUpsertManifest(w http.ResponseWriter, r *http.Request) {
	var dto upsertOAuthManifestRequest
	if err := decodeJSON(r, &dto); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body.")
		return
	}
	err := s.deps.Resolver.UpsertOAuth(r.Context(), fromManifestRequest(dto))
	var slugErr manifests.ErrInvalidSlug
	if errors.As(err, &slugErr) {
		writeError(w, http.StatusBadRequest, slugErr.Error())
		return
	}
	if writeServiceError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, keyResponse{Key: dto.Key})
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	var dto discoverOidcRequest
	if err := decodeJSON(r, &dto); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body.")
		return
	}
	m, err := s.deps.Discovery.Discover(r.Context(), derefOr(dto.URL, ""))
	if err != nil {
		writeError(w, http.StatusBadRequest, "discovery failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toManifestDTO(*m, false))
}

func (s *Server) handleDeleteManifest(w http.ResponseWriter, r *http.Request) {
	deleted, err := s.deps.Resolver.Delete(r.Context(), chi.URLParam(r, "kind"), chi.URLParam(r, "key"))
	if writeServiceError(w, err) {
		return
	}
	noContentOrNotFound(w, deleted)
}

// ---- oauth configs ----

func (s *Server) handleListConfigs(w http.ResponseWriter, r *http.Request) {
	items, err := s.deps.OAuthConfigs.List(r.Context())
	if writeServiceError(w, err) {
		return
	}
	out := make([]oauthConfigDTO, len(items))
	for i, c := range items {
		out[i] = toConfigDTO(c)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleUpsertConfig(w http.ResponseWriter, r *http.Request) {
	var dto upsertOAuthConfigRequest
	if err := decodeJSON(r, &dto); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body.")
		return
	}
	id, err := s.deps.OAuthConfigs.Upsert(r.Context(), dto.Provider, dto.ClientID, dto.ClientSecret, dto.Scopes, dto.RedirectURI)
	if writeServiceError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, oauthConfigCreatedResponse{ID: id, Provider: dto.Provider})
}

func (s *Server) handleDeleteConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := uuidParam(chi.URLParam(r, "id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id.")
		return
	}
	deleted, err := s.deps.OAuthConfigs.Delete(r.Context(), id)
	if writeServiceError(w, err) {
		return
	}
	noContentOrNotFound(w, deleted)
}

// ---- oauth tokens ----

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	items, err := s.deps.OAuthTokens.List(r.Context())
	if writeServiceError(w, err) {
		return
	}
	out := make([]oauthTokenDTO, len(items))
	for i, t := range items {
		out[i] = toTokenDTO(t)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	id, ok := uuidParam(chi.URLParam(r, "id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id.")
		return
	}
	deleted, err := s.deps.OAuthTokens.Delete(r.Context(), id)
	if writeServiceError(w, err) {
		return
	}
	noContentOrNotFound(w, deleted)
}

func (s *Server) handleGetToken(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	account := r.URL.Query().Get("account")
	token, err := s.deps.OAuthTokens.GetAccessToken(r.Context(), provider, account)
	if writeServiceError(w, err) {
		return
	}
	if token == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, oauthAccessTokenResponse{AccessToken: token.AccessToken, ExpiresAt: token.ExpiresAt, Scopes: orEmpty(token.Scopes)})
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	var scopes []string
	if raw := r.URL.Query().Get("scopes"); raw != "" {
		scopes = strings.FieldsFunc(raw, func(c rune) bool { return c == ' ' || c == ',' })
	}
	res, err := s.deps.OAuthFlow.Begin(r.Context(), provider, scopes, s.deps.PublicBaseURL)
	if writeServiceError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, connectResponse{AuthorizeURL: res.AuthorizeURL})
}

// ---- oauth callback (anonymous) ----

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		redirect(w, r, "/oauthconnect?oauth_error="+url.QueryEscape(e))
		return
	}
	code, state := q.Get("code"), q.Get("state")
	if code == "" || state == "" {
		redirect(w, r, "/oauthconnect?oauth_error=missing_code")
		return
	}
	res, err := s.deps.OAuthFlow.Complete(r.Context(), code, state)
	if err != nil {
		var ae service.OAuthAuthorizationError
		if errors.As(err, &ae) {
			redirect(w, r, "/oauthconnect?oauth_error="+url.QueryEscape(ae.Message))
			return
		}
		redirect(w, r, "/oauthconnect?oauth_error="+url.QueryEscape("internal error"))
		return
	}
	redirect(w, r, "/oauthconnect?connected="+url.QueryEscape(res.Provider))
}

// ---- audit ----

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	query := audit.Query{Limit: atoiOr(q.Get("limit"), 50), Offset: atoiOr(q.Get("offset"), 0)}
	if t, ok := audit.ParseEventType(q.Get("type")); ok {
		query.Type = &t
	}
	if o, ok := audit.ParseOutcome(q.Get("outcome")); ok {
		query.Outcome = &o
	}
	if u, ok := uuidParam(q.Get("userId")); ok {
		query.UserID = &u
	}
	since, ok := parseTimeParam(q.Get("since"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid 'since' timestamp (RFC3339 expected).")
		return
	}
	query.Since = since
	until, ok := parseTimeParam(q.Get("until"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid 'until' timestamp (RFC3339 expected).")
		return
	}
	query.Until = until

	result, err := s.deps.AuditQuery.Query(r.Context(), query)
	if writeServiceError(w, err) {
		return
	}
	items := make([]auditEventDTO, len(result.Items))
	for i, e := range result.Items {
		items[i] = toAuditDTO(e)
	}
	writeJSON(w, http.StatusOK, auditPageResponse{Items: items, Total: result.Total, Limit: result.Limit, Offset: result.Offset})
}

// ---- helpers ----

func noContentOrNotFound(w http.ResponseWriter, deleted bool) {
	if deleted {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func redirect(w http.ResponseWriter, r *http.Request, to string) {
	http.Redirect(w, r, to, http.StatusFound)
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

// parseTimeParam parses an optional RFC3339 query value: ("", true) when absent, (nil, false) on
// garbage — a malformed filter must be a 400, not silently unfiltered results.
func parseTimeParam(s string) (*time.Time, bool) {
	if s == "" {
		return nil, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t, true
	}
	return nil, false
}

// identity carried for the /me endpoint (JWT callers only).
type meIdentity struct {
	Email *string
	Name  *string
}

type identityKeyT struct{}

func withIdentity(ctx context.Context, id meIdentity) context.Context {
	return context.WithValue(ctx, identityKeyT{}, id)
}

func identityFrom(ctx context.Context) meIdentity {
	if id, ok := ctx.Value(identityKeyT{}).(meIdentity); ok {
		return id
	}
	return meIdentity{}
}
