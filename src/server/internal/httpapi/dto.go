// Package httpapi is the HTTP/JSON transport: a chi router, OIDC/JWT + access-key authentication,
// the uniform scope gate, the per-request audit/caller context, and handlers that call the domain
// services. The DTOs below define the exact camelCase wire contract, so the generated Go CLI client
// and the React SPA keep working unchanged.
package httpapi

import (
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/manifests"
	"donkeywork.dev/vault-server/internal/service"
	"donkeywork.dev/vault-server/internal/store"
)

type meResponse struct {
	UserID   *string `json:"userId"`
	TenantID string  `json:"tenantId"`
	Email    *string `json:"email"`
	Name     *string `json:"name"`
}

type appConfigResponse struct {
	Authority            string `json:"authority"`
	ClientID             string `json:"clientId"`
	Scopes               string `json:"scopes"`
	AuthEnabled          bool   `json:"authEnabled"`
	CliClientID          string `json:"cliClientId"`
	CliScopes            string `json:"cliScopes"`
	RequireHTTPSMetadata bool   `json:"requireHttpsMetadata"`
}

type apiKeyDTO struct {
	ID          uuid.UUID                `json:"id"`
	Name        string                   `json:"name"`
	Description *string                  `json:"description"`
	BaseURL     *string                  `json:"baseUrl"`
	DocsURL     *string                  `json:"docsUrl"`
	Header      *string                  `json:"header"`
	Prefix      *string                  `json:"prefix"`
	Username    *string                  `json:"username"`
	Kind        contracts.CredentialKind `json:"kind"`
	CreatedAt   time.Time                `json:"createdAt"`
	LastUsedAt  *time.Time               `json:"lastUsedAt"`
}

type createAPIKeyRequest struct {
	Name        string                   `json:"name"`
	Secret      *string                  `json:"secret"`
	Description *string                  `json:"description"`
	BaseURL     *string                  `json:"baseUrl"`
	DocsURL     *string                  `json:"docsUrl"`
	Header      *string                  `json:"header"`
	Prefix      *string                  `json:"prefix"`
	Username    *string                  `json:"username"`
	Kind        contracts.CredentialKind `json:"kind"`
}

type createdAPIKeyResponse struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

type revealAPIKeyResponse struct {
	Secret      string                   `json:"secret"`
	Header      string                   `json:"header"`
	HeaderValue string                   `json:"headerValue"`
	Prefix      string                   `json:"prefix"`
	BaseURL     string                   `json:"baseUrl"`
	DocsURL     string                   `json:"docsUrl"`
	Description string                   `json:"description"`
	Scheme      string                   `json:"scheme"`
	Username    string                   `json:"username"`
	Kind        contracts.CredentialKind `json:"kind"`
}

type credentialShapeResponse struct {
	Header      string                   `json:"header"`
	Prefix      string                   `json:"prefix"`
	BaseURL     string                   `json:"baseUrl"`
	DocsURL     string                   `json:"docsUrl"`
	Description string                   `json:"description"`
	Scheme      string                   `json:"scheme"`
	Username    string                   `json:"username"`
	Kind        contracts.CredentialKind `json:"kind"`
}

type accessKeyDTO struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	Description *string    `json:"description"`
	Scopes      []string   `json:"scopes"`
	Enabled     bool       `json:"enabled"`
	Prefix      string     `json:"prefix"`
	CreatedAt   time.Time  `json:"createdAt"`
	LastUsedAt  *time.Time `json:"lastUsedAt"`
	ExpiresAt   *time.Time `json:"expiresAt"`
}

type createAccessKeyRequest struct {
	Name        string     `json:"name"`
	Description *string    `json:"description"`
	Scopes      []string   `json:"scopes"`
	ExpiresAt   *time.Time `json:"expiresAt"`
}

type createdAccessKeyResponse struct {
	ID     uuid.UUID `json:"id"`
	Name   string    `json:"name"`
	Scopes []string  `json:"scopes"`
	Secret string    `json:"secret"`
}

type setEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

type accessKeyEnabledResponse struct {
	ID      uuid.UUID `json:"id"`
	Enabled bool      `json:"enabled"`
}

type oauthScopeDTO struct {
	Value       string `json:"value"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Sensitive   bool   `json:"sensitive"`
}

type oauthManifestDTO struct {
	ID                    uuid.UUID         `json:"id"`
	ParentID              uuid.UUID         `json:"parentId"`
	Key                   string            `json:"key"`
	Name                  string            `json:"name"`
	IconURL               string            `json:"iconUrl"`
	DocsURL               string            `json:"docsUrl"`
	Template              bool              `json:"template"`
	AuthorizationEndpoint string            `json:"authorizationEndpoint"`
	TokenEndpoint         string            `json:"tokenEndpoint"`
	UserinfoEndpoint      string            `json:"userinfoEndpoint"`
	ScopeDelimiter        string            `json:"scopeDelimiter"`
	DefaultScopes         []string          `json:"defaultScopes"`
	Scopes                []oauthScopeDTO   `json:"scopes"`
	AuthorizeParams       map[string]string `json:"authorizeParams"`
}

type upsertOAuthManifestRequest struct {
	Key                   string            `json:"key"`
	ParentID              uuid.UUID         `json:"parentId"`
	Name                  *string           `json:"name"`
	IconURL               *string           `json:"iconUrl"`
	DocsURL               *string           `json:"docsUrl"`
	AuthorizationEndpoint *string           `json:"authorizationEndpoint"`
	TokenEndpoint         *string           `json:"tokenEndpoint"`
	UserinfoEndpoint      *string           `json:"userinfoEndpoint"`
	ScopeDelimiter        *string           `json:"scopeDelimiter"`
	DefaultScopes         []string          `json:"defaultScopes"`
	Scopes                []oauthScopeDTO   `json:"scopes"`
	AuthorizeParams       map[string]string `json:"authorizeParams"`
}

type discoverOidcRequest struct {
	URL *string `json:"url"`
}

type keyResponse struct {
	Key string `json:"key"`
}

type oauthConfigDTO struct {
	ID             uuid.UUID `json:"id"`
	Provider       string    `json:"provider"`
	ClientIDMasked string    `json:"clientIdMasked"`
	Scopes         []string  `json:"scopes"`
	RedirectURI    *string   `json:"redirectUri"`
	CreatedAt      time.Time `json:"createdAt"`
}

type upsertOAuthConfigRequest struct {
	Provider     string   `json:"provider"`
	ClientID     string   `json:"clientId"`
	ClientSecret *string  `json:"clientSecret"`
	Scopes       []string `json:"scopes"`
	RedirectURI  *string  `json:"redirectUri"`
}

type oauthConfigCreatedResponse struct {
	ID       uuid.UUID `json:"id"`
	Provider string    `json:"provider"`
}

type oauthTokenDTO struct {
	ID              uuid.UUID  `json:"id"`
	Provider        string     `json:"provider"`
	Account         string     `json:"account"`
	ExpiresAt       *time.Time `json:"expiresAt"`
	LastRefreshedAt *time.Time `json:"lastRefreshedAt"`
	Scopes          []string   `json:"scopes"`
}

type oauthAccessTokenResponse struct {
	AccessToken string     `json:"accessToken"`
	ExpiresAt   *time.Time `json:"expiresAt"`
	Scopes      []string   `json:"scopes"`
}

type connectResponse struct {
	AuthorizeURL string `json:"authorizeUrl"`
}

type auditEventDTO struct {
	ID              uuid.UUID `json:"id"`
	Type            string    `json:"type"`
	Outcome         string    `json:"outcome"`
	UserID          uuid.UUID `json:"userId"`
	TenantID        uuid.UUID `json:"tenantId"`
	AccessKeyPrefix *string   `json:"accessKeyPrefix"`
	AccessKeyName   *string   `json:"accessKeyName"`
	SourceIP        *string   `json:"sourceIp"`
	TargetKind      *string   `json:"targetKind"`
	TargetProvider  *string   `json:"targetProvider"`
	TargetAccount   *string   `json:"targetAccount"`
	TargetName      *string   `json:"targetName"`
	Transport       string    `json:"transport"`
	Method          *string   `json:"method"`
	Detail          *string   `json:"detail"`
	CreatedAt       time.Time `json:"createdAt"`
}

type auditPageResponse struct {
	Items  []auditEventDTO `json:"items"`
	Total  int             `json:"total"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
}

type mcpConnectionDTO struct {
	ID                    uuid.UUID  `json:"id"`
	Slug                  string     `json:"slug"`
	Name                  string     `json:"name"`
	Description           *string    `json:"description"`
	UpstreamURL           string     `json:"upstreamUrl"`
	AuthMode              string     `json:"authMode"`
	AuditMode             string     `json:"auditMode"`
	ProtocolVersion       string     `json:"protocolVersion"`
	UpstreamProtocolMode  string     `json:"upstreamProtocolMode"`
	LegacyProtocolVersion string     `json:"legacyProtocolVersion"`
	ProtocolEra           string     `json:"protocolEra"`
	ProbeStatus           string     `json:"probeStatus"`
	ProbeCheckedAt        *time.Time `json:"probeCheckedAt"`
	ProbeError            *string    `json:"probeError"`
	ProbeDetail           *string    `json:"probeDetail"`
	SupportedVersions     []string   `json:"supportedVersions"`
	ServerName            *string    `json:"serverName"`
	ServerVersion         *string    `json:"serverVersion"`
	Enabled               bool       `json:"enabled"`
	CreatedAt             time.Time  `json:"createdAt"`
	UpdatedAt             *time.Time `json:"updatedAt"`
}

type upsertMCPConnectionRequest struct {
	ID                    uuid.UUID `json:"id"`
	Slug                  string    `json:"slug"`
	Name                  string    `json:"name"`
	Description           *string   `json:"description"`
	UpstreamURL           string    `json:"upstreamUrl"`
	AuthMode              string    `json:"authMode"`
	AuditMode             string    `json:"auditMode"`
	UpstreamProtocolMode  string    `json:"upstreamProtocolMode"`
	LegacyProtocolVersion string    `json:"legacyProtocolVersion"`
	Enabled               *bool     `json:"enabled"`
}

type mcpGrantDTO struct {
	ID           uuid.UUID `json:"id"`
	ConnectionID uuid.UUID `json:"connectionId"`
	AccessKeyID  uuid.UUID `json:"accessKeyId"`
	CreatedAt    time.Time `json:"createdAt"`
}

type createMCPGrantRequest struct {
	AccessKeyID uuid.UUID `json:"accessKeyId"`
}

type createMCPEvalRunRequest struct {
	RunID         string      `json:"runId"`
	ConnectionIDs []uuid.UUID `json:"connectionIds"`
	ExpiresAt     time.Time   `json:"expiresAt"`
}

type mcpEvalRunConnectionDTO struct {
	ID       uuid.UUID `json:"id"`
	Slug     string    `json:"slug"`
	Name     string    `json:"name"`
	ProxyURL string    `json:"proxyUrl"`
}

type mcpEvalRunDTO struct {
	ID          uuid.UUID  `json:"id"`
	RunID       string     `json:"runId"`
	AccessKeyID uuid.UUID  `json:"accessKeyId"`
	ExpiresAt   time.Time  `json:"expiresAt"`
	RevokedAt   *time.Time `json:"revokedAt"`
	CreatedAt   time.Time  `json:"createdAt"`
}

type createdMCPEvalRunResponse struct {
	mcpEvalRunDTO
	Secret      string                    `json:"secret"`
	Connections []mcpEvalRunConnectionDTO `json:"connections"`
}

type mcpHeaderBindingDTO struct {
	ID           uuid.UUID `json:"id"`
	ConnectionID uuid.UUID `json:"connectionId"`
	CredentialID uuid.UUID `json:"credentialId"`
	HeaderName   *string   `json:"headerName"`
	CreatedAt    time.Time `json:"createdAt"`
}

type createMCPHeaderBindingRequest struct {
	CredentialID uuid.UUID `json:"credentialId"`
	HeaderName   *string   `json:"headerName"`
}

type mcpToolPolicyDTO struct {
	ID           uuid.UUID  `json:"id"`
	ConnectionID uuid.UUID  `json:"connectionId"`
	Method       string     `json:"method"`
	ToolName     string     `json:"toolName"`
	Allow        bool       `json:"allow"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    *time.Time `json:"updatedAt"`
}

type upsertMCPToolPolicyRequest struct {
	Method   string `json:"method"`
	ToolName string `json:"toolName"`
	Allow    bool   `json:"allow"`
}

type configureMCPOAuthRequest struct {
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret"`
	Scopes       []string `json:"scopes"`
}

type mcpOAuthConnectResponse struct {
	AuthorizeURL string    `json:"authorizeUrl"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

type mcpAuditMessageDTO struct {
	ID               uuid.UUID `json:"id"`
	ExchangeID       uuid.UUID `json:"exchangeId"`
	ConnectionID     uuid.UUID `json:"connectionId"`
	SequenceNo       int64     `json:"sequenceNo"`
	ObservedAt       time.Time `json:"observedAt"`
	Direction        string    `json:"direction"`
	MessageKind      string    `json:"messageKind"`
	PolicyDecision   string    `json:"policyDecision"`
	JSONRPCIDType    *string   `json:"jsonrpcIdType"`
	JSONRPCIDText    *string   `json:"jsonrpcIdText"`
	Method           *string   `json:"method"`
	ToolName         *string   `json:"toolName"`
	PolicyRule       *string   `json:"policyRule"`
	ResultType       *string   `json:"resultType"`
	SubscriptionID   *string   `json:"subscriptionId"`
	ErrorCode        *int      `json:"errorCode"`
	PayloadRedacted  *string   `json:"payloadRedacted"`
	PayloadBytes     int64     `json:"payloadBytes"`
	PayloadTruncated bool      `json:"payloadTruncated"`
	RedactionPaths   []string  `json:"redactionPaths"`
}

type mcpAuditPageResponse struct {
	Items  []mcpAuditMessageDTO `json:"items"`
	Total  int                  `json:"total"`
	Limit  int                  `json:"limit"`
	Offset int                  `json:"offset"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// ---- mappers ----

func toAPIKeyDTO(k service.StoredAPIKey) apiKeyDTO {
	return apiKeyDTO{
		ID: k.ID, Name: k.Name, Description: k.Description, BaseURL: k.BaseURL, DocsURL: k.DocsURL,
		Header: k.Header, Prefix: k.Prefix, Username: k.Username, Kind: k.Kind, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt,
	}
}

func toAccessKeyDTO(k service.StoredAccessKey) accessKeyDTO {
	return accessKeyDTO{
		ID: k.ID, Name: k.Name, Description: k.Description, Scopes: orEmpty(k.Scopes),
		Enabled: k.Enabled, Prefix: k.Prefix, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt,
		ExpiresAt: k.ExpiresAt,
	}
}

func toManifestDTO(m manifests.Manifest, template bool) oauthManifestDTO {
	scopes := make([]oauthScopeDTO, len(m.Scopes))
	for i, s := range m.Scopes {
		scopes[i] = oauthScopeDTO{Value: s.Value, Description: s.Description, Category: s.Category, Sensitive: s.Sensitive}
	}
	params := m.AuthorizeParams
	if params == nil {
		params = map[string]string{}
	}
	return oauthManifestDTO{
		ID: m.ID, ParentID: m.ParentID, Key: m.Key, Name: m.Name, IconURL: m.IconURL, DocsURL: m.DocsURL,
		Template: template, AuthorizationEndpoint: m.AuthorizationEndpoint, TokenEndpoint: m.TokenEndpoint,
		UserinfoEndpoint: m.UserinfoEndpoint, ScopeDelimiter: m.ScopeDelimiter, DefaultScopes: orEmpty(m.DefaultScopes),
		Scopes: scopes, AuthorizeParams: params,
	}
}

func fromManifestRequest(dto upsertOAuthManifestRequest) manifests.Manifest {
	scopes := make([]manifests.ScopeDef, len(dto.Scopes))
	for i, s := range dto.Scopes {
		scopes[i] = manifests.ScopeDef{Value: s.Value, Description: s.Description, Category: s.Category, Sensitive: s.Sensitive}
	}
	delim := derefOr(dto.ScopeDelimiter, " ")
	if delim == "" {
		delim = " "
	}
	params := dto.AuthorizeParams
	if params == nil {
		params = map[string]string{}
	}
	return manifests.Manifest{
		Key: dto.Key, ParentID: dto.ParentID, Name: derefOr(dto.Name, ""), IconURL: derefOr(dto.IconURL, ""),
		DocsURL: derefOr(dto.DocsURL, ""), AuthorizationEndpoint: derefOr(dto.AuthorizationEndpoint, ""),
		TokenEndpoint: derefOr(dto.TokenEndpoint, ""), UserinfoEndpoint: derefOr(dto.UserinfoEndpoint, ""),
		ScopeDelimiter: delim, DefaultScopes: orEmpty(dto.DefaultScopes), Scopes: scopes, AuthorizeParams: params,
	}
}

func toConfigDTO(c service.OAuthConfigSummary) oauthConfigDTO {
	return oauthConfigDTO{ID: c.ID, Provider: c.Provider, ClientIDMasked: c.ClientIDMasked, Scopes: orEmpty(c.Scopes), RedirectURI: c.RedirectURI, CreatedAt: c.CreatedAt}
}

func toTokenDTO(t service.OAuthTokenSummary) oauthTokenDTO {
	return oauthTokenDTO{ID: t.ID, Provider: t.Provider, Account: t.Account, ExpiresAt: t.ExpiresAt, LastRefreshedAt: t.LastRefreshedAt, Scopes: orEmpty(t.Scopes)}
}

func toAuditDTO(e store.AuditEntry) auditEventDTO {
	return auditEventDTO{
		ID: e.ID, Type: audit.EventType(e.EventType).String(), Outcome: audit.Outcome(e.Outcome).String(),
		UserID: e.UserID, TenantID: e.TenantID, AccessKeyPrefix: e.AccessKeyPrefix, AccessKeyName: e.AccessKeyName,
		SourceIP: e.SourceIP, TargetKind: e.TargetKind, TargetProvider: e.TargetProvider, TargetAccount: e.TargetAccount,
		TargetName: e.TargetName, Transport: e.Transport, Method: e.Method, Detail: e.Detail, CreatedAt: e.CreatedAt,
	}
}

func toMCPConnectionDTO(c store.MCPConnection) mcpConnectionDTO {
	return mcpConnectionDTO{ID: c.ID, Slug: c.Slug, Name: c.Name, Description: c.Description,
		UpstreamURL: c.UpstreamURL, AuthMode: c.AuthMode, AuditMode: c.AuditMode,
		ProtocolVersion: c.ProtocolVersion, UpstreamProtocolMode: c.UpstreamProtocolMode,
		LegacyProtocolVersion: c.LegacyProtocolVersion, ProtocolEra: c.ProtocolEra, ProbeStatus: c.ProbeStatus,
		ProbeCheckedAt: c.ProbeCheckedAt, ProbeError: c.ProbeError, ProbeDetail: c.ProbeDetail,
		SupportedVersions: orEmpty(c.SupportedVersions), ServerName: c.ServerName, ServerVersion: c.ServerVersion,
		Enabled: c.Enabled, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}

func toMCPAuditMessageDTO(m store.MCPAuditMessage) mcpAuditMessageDTO {
	return mcpAuditMessageDTO{ID: m.ID, ExchangeID: m.ExchangeID, ConnectionID: m.ConnectionID,
		SequenceNo: m.SequenceNo, ObservedAt: m.ObservedAt, Direction: m.Direction,
		MessageKind: m.MessageKind, PolicyDecision: m.PolicyDecision, JSONRPCIDType: m.JSONRPCIDType,
		JSONRPCIDText: m.JSONRPCIDText, Method: m.Method, ToolName: m.ToolName, PolicyRule: m.PolicyRule,
		ResultType: m.ResultType, SubscriptionID: m.SubscriptionID, ErrorCode: m.ErrorCode,
		PayloadRedacted: m.PayloadRedacted, PayloadBytes: m.PayloadBytes,
		PayloadTruncated: m.PayloadTruncated, RedactionPaths: orEmpty(m.RedactionPaths)}
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func derefOr(s *string, def string) string {
	if s == nil {
		return def
	}
	return *s
}
