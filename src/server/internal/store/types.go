// Package store is the persistence layer. It deliberately uses hand-written SQL over pgx rather than
// an ORM: the schema is small and CRUD-shaped, and for a credential vault the exact SQL that touches
// the secret and audit tables should be visible and auditable. Every query is scoped to a user id
// passed explicitly (a per-user query filter); a handful of methods take an explicit owner id for
// the anonymous OAuth callback, which has no ambient caller.
//
// The structs below map 1:1 to the existing `vault` schema tables; column names and types are
// unchanged so deployments upgrade in place on the same data.
package store

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrOwnershipMismatch reports that related rows do not share the requested owner and tenant.
var ErrOwnershipMismatch = errors.New("store ownership mismatch")

// AccessKey is a scoped authentication credential ("dwv_…"). Only the SHA-256 hash is stored.
type AccessKey struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	TenantID    uuid.UUID
	Name        string
	Description *string
	KeyHash     []byte
	KeyPrefix   string
	Scopes      []string
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   *time.Time
	LastUsedAt  *time.Time
	ExpiresAt   *time.Time
}

// APIKey is a self-describing, non-OAuth credential. FieldsCipher is the envelope-encrypted secret.
type APIKey struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	TenantID     uuid.UUID
	ProviderKey  string
	Name         string
	FieldsCipher []byte
	Kind         string
	Description  *string
	BaseURL      *string
	DocsURL      *string
	HeaderName   *string
	Prefix       *string
	Username     *string
	CreatedAt    time.Time
	UpdatedAt    *time.Time
	LastUsedAt   *time.Time
}

// OAuthProviderConfig holds per-user OAuth app credentials (client id/secret are envelope-encrypted).
type OAuthProviderConfig struct {
	ID                 uuid.UUID
	UserID             uuid.UUID
	TenantID           uuid.UUID
	ProviderID         uuid.UUID
	ProviderKey        string
	ClientIDCipher     []byte
	ClientSecretCipher []byte
	ScopesJSON         *string
	RedirectURI        *string
	CreatedAt          time.Time
	UpdatedAt          *time.Time
}

// OAuthState is a one-time PKCE/state row for an in-flight authorization (no user filter).
type OAuthState struct {
	ID            uuid.UUID
	State         string
	Provider      string
	CodeVerifier  string
	OwnerUserID   uuid.UUID
	OwnerTenantID uuid.UUID
	RedirectURI   string
	ExpiresAt     time.Time
	CreatedAt     time.Time
}

// OAuthToken is a stored token set for a provider + account (tokens are envelope-encrypted).
type OAuthToken struct {
	ID                 uuid.UUID
	UserID             uuid.UUID
	TenantID           uuid.UUID
	ProviderID         uuid.UUID
	ProviderKey        string
	Account            string
	AccessTokenCipher  []byte
	RefreshTokenCipher []byte
	ScopesJSON         *string
	ExpiresAt          *time.Time
	LastRefreshedAt    *time.Time
	CreatedAt          time.Time
	UpdatedAt          *time.Time
}

// ProviderManifest is a DB-stored custom OAuth provider manifest (serialized as JSON).
type ProviderManifest struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	TenantID     uuid.UUID
	Kind         string
	Key          string
	ProviderID   uuid.UUID
	ParentID     uuid.UUID
	DocumentJSON string
	CreatedAt    time.Time
	UpdatedAt    *time.Time
}

// AuditEntry is one append-only audit row. It never carries secret material.
type AuditEntry struct {
	ID              uuid.UUID
	EventType       int
	Outcome         int
	UserID          uuid.UUID
	TenantID        uuid.UUID
	AccessKeyID     *uuid.UUID
	AccessKeyPrefix *string
	AccessKeyName   *string
	SourceIP        *string
	Headers         map[string]string
	TargetKind      *string
	TargetProvider  *string
	TargetAccount   *string
	TargetName      *string
	Transport       string
	Method          *string
	Detail          *string
	CreatedAt       time.Time
}

// AuditFilter is the parameter set for an audit query (already clamped by the caller).
type AuditFilter struct {
	UserID       uuid.UUID
	TenantID     uuid.UUID
	Limit        int
	Offset       int
	EventType    *int
	Outcome      *int
	FilterUserID *uuid.UUID
	Since        *time.Time
	Until        *time.Time
}

// MCPConnection configures one stateless MCP upstream exposed through the gateway.
type MCPConnection struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	TenantID        uuid.UUID
	Slug            string
	Name            string
	Description     *string
	UpstreamURL     string
	AuthMode        string
	AuditMode       string
	ProtocolVersion string
	Enabled         bool
	CreatedAt       time.Time
	UpdatedAt       *time.Time
}

// MCPConnectionGrant authorizes one vault access key to use one MCP connection.
type MCPConnectionGrant struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	TenantID     uuid.UUID
	ConnectionID uuid.UUID
	AccessKeyID  uuid.UUID
	CreatedAt    time.Time
}

// MCPHeaderBinding maps an existing encrypted API-key credential to an upstream header.
type MCPHeaderBinding struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	TenantID     uuid.UUID
	ConnectionID uuid.UUID
	CredentialID uuid.UUID
	HeaderName   *string
	CreatedAt    time.Time
}

// MCPToolPolicy records an allow or deny decision for a method and optional tool name.
type MCPToolPolicy struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	TenantID     uuid.UUID
	ConnectionID uuid.UUID
	Method       string
	ToolName     string
	Allow        bool
	CreatedAt    time.Time
	UpdatedAt    *time.Time
}

// MCPOAuthAuthorization is the connection-bound OAuth client and token set for an MCP upstream.
// Every credential or token field is stored as an encrypted envelope.
type MCPOAuthAuthorization struct {
	ID                    uuid.UUID
	UserID                uuid.UUID
	TenantID              uuid.UUID
	ConnectionID          uuid.UUID
	IssuerURL             *string
	AuthorizationEndpoint *string
	TokenEndpoint         *string
	Resource              *string
	TokenType             *string
	TokenAuthMethod       string
	ClientIDCipher        []byte
	ClientSecretCipher    []byte
	AccessTokenCipher     []byte
	RefreshTokenCipher    []byte
	Scopes                []string
	ExpiresAt             *time.Time
	LastRefreshedAt       *time.Time
	CreatedAt             time.Time
	UpdatedAt             *time.Time
}

// MCPOAuthState is a single-use PKCE authorization flow bound to one MCP connection.
type MCPOAuthState struct {
	State           string
	ConnectionID    uuid.UUID
	UserID          uuid.UUID
	TenantID        uuid.UUID
	CodeVerifier    string
	RedirectURI     string
	Resource        string
	IssuerURL       string
	AuthEndpoint    string
	TokenEndpoint   string
	TokenAuthMethod string
	Scopes          []string
	ExpiresAt       time.Time
	CreatedAt       time.Time
}

// MCPAuditExchange records the HTTP-level envelope around one stateless MCP request.
type MCPAuditExchange struct {
	ID                  uuid.UUID
	ConnectionID        uuid.UUID
	UserID              uuid.UUID
	TenantID            uuid.UUID
	AccessKeyID         uuid.UUID
	EvalRunID           *string
	DownstreamRequestID *string
	UpstreamRequestID   *string
	RemoteAddress       *string
	UserAgent           *string
	TraceID             *string
	ErrorClass          *string
	HTTPMethod          string
	ProtocolVersion     string
	Outcome             string
	StartedAt           time.Time
	CompletedAt         *time.Time
	StatusCode          *int
	RequestBytes        int64
	ResponseBytes       int64
}

// MCPAuditMessage records one inspected JSON-RPC message within an MCP exchange.
type MCPAuditMessage struct {
	ID                 uuid.UUID
	ExchangeID         uuid.UUID
	ConnectionID       uuid.UUID
	UserID             uuid.UUID
	TenantID           uuid.UUID
	SequenceNo         int64
	ObservedAt         time.Time
	Direction          string
	MessageKind        string
	PolicyDecision     string
	JSONRPCIDType      *string
	JSONRPCIDText      *string
	Method             *string
	ToolName           *string
	PolicyRule         *string
	ResultType         *string
	SubscriptionID     *string
	ErrorCode          *int
	RequestStateDigest []byte
	PayloadRedacted    *string
	PayloadSHA256      []byte
	PayloadBytes       int64
	PayloadTruncated   bool
	RedactionPaths     []string
}

// MCPAuditFilter is the owner-scoped parameter set for querying inspected MCP messages.
type MCPAuditFilter struct {
	UserID         uuid.UUID
	TenantID       uuid.UUID
	Limit          int
	Offset         int
	ConnectionID   *uuid.UUID
	AccessKeyID    *uuid.UUID
	EvalRunID      *string
	Direction      *string
	Method         *string
	ToolName       *string
	PolicyDecision *string
	Since          *time.Time
	Until          *time.Time
}
