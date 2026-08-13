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
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ErrOwnershipMismatch reports that related rows do not share the requested owner and tenant.
var ErrOwnershipMismatch = errors.New("store ownership mismatch")

// ErrInvalidMCPToolParameterHeader reports malformed or duplicate parameter-header metadata.
var ErrInvalidMCPToolParameterHeader = errors.New("invalid MCP tool parameter header")

// ErrInvalidMCPProtocolProbe reports an unsupported persisted probe era or status.
var ErrInvalidMCPProtocolProbe = errors.New("invalid MCP protocol probe")

// ErrInvalidMCPEvalRun reports an invalid atomic eval-run creation request.
var ErrInvalidMCPEvalRun = errors.New("invalid MCP eval run")

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
	ID                    uuid.UUID
	UserID                uuid.UUID
	TenantID              uuid.UUID
	Slug                  string
	Name                  string
	Description           *string
	UpstreamURL           string
	AuthMode              string
	AuditMode             string
	ProtocolVersion       string
	UpstreamProtocolMode  string
	LegacyProtocolVersion string
	ProtocolEra           string
	ProbeStatus           string
	ProbeCheckedAt        *time.Time
	ProbeError            *string
	ProbeDetail           *string
	SupportedVersions     []string
	ServerName            *string
	ServerVersion         *string
	Enabled               bool
	CreatedAt             time.Time
	UpdatedAt             *time.Time
}

// MCPProtocolProbeResult is the bounded, secret-free result of probing one MCP connection.
type MCPProtocolProbeResult struct {
	ConnectionID      uuid.UUID
	UserID            uuid.UUID
	TenantID          uuid.UUID
	ProtocolEra       string
	Status            string
	CheckedAt         time.Time
	Error             *string
	Detail            *string
	SupportedVersions []string
	ServerName        *string
	ServerVersion     *string
}

// ValidateMCPProtocolProbe verifies the bounded enum and text values stored for a probe.
func ValidateMCPProtocolProbe(result MCPProtocolProbeResult) error {
	validEra := result.ProtocolEra == "unknown" || result.ProtocolEra == "modern_2026_07" || result.ProtocolEra == "legacy_session_likely" || result.ProtocolEra == "incompatible"
	validStatus := result.Status == "not_checked" || result.Status == "compatible" || result.Status == "incompatible" || result.Status == "auth_required" || result.Status == "unreachable" || result.Status == "error"
	if !validEra || !validStatus || result.CheckedAt.IsZero() {
		return ErrInvalidMCPProtocolProbe
	}
	if result.Error != nil && len(*result.Error) > 255 || result.Detail != nil && len(*result.Detail) > 1024 ||
		result.ServerName != nil && len(*result.ServerName) > 255 || result.ServerVersion != nil && len(*result.ServerVersion) > 255 {
		return ErrInvalidMCPProtocolProbe
	}
	for _, version := range result.SupportedVersions {
		if strings.TrimSpace(version) == "" || len(version) > 64 {
			return ErrInvalidMCPProtocolProbe
		}
	}
	return nil
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

// MCPEvalRun owns a short-lived MCP access key and its connection grants.
type MCPEvalRun struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	TenantID    uuid.UUID
	RunID       string
	AccessKeyID uuid.UUID
	ExpiresAt   time.Time
	RevokedAt   *time.Time
	CreatedAt   time.Time
}

// ValidateMCPEvalRunCreation verifies the non-secret inputs to atomic eval-run creation.
func ValidateMCPEvalRunCreation(run *MCPEvalRun, key *AccessKey, connectionIDs []uuid.UUID, now time.Time) error {
	if run == nil || key == nil || strings.TrimSpace(run.RunID) == "" || len(run.RunID) > 255 ||
		run.UserID == uuid.Nil || key.UserID != run.UserID || key.TenantID != run.TenantID ||
		!key.Enabled || len(key.KeyHash) == 0 || key.KeyPrefix == "" || key.ExpiresAt == nil ||
		!run.ExpiresAt.Equal(*key.ExpiresAt) || !run.ExpiresAt.After(now) || len(connectionIDs) == 0 ||
		len(key.Scopes) != 1 || key.Scopes[0] != "vault:mcp" {
		return ErrInvalidMCPEvalRun
	}
	seen := make(map[uuid.UUID]struct{}, len(connectionIDs))
	for _, connectionID := range connectionIDs {
		if connectionID == uuid.Nil {
			return ErrInvalidMCPEvalRun
		}
		if _, exists := seen[connectionID]; exists {
			return ErrInvalidMCPEvalRun
		}
		seen[connectionID] = struct{}{}
	}
	return nil
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

// MCPToolParameterHeader maps one discovered tool argument path to an MCP parameter header.
type MCPToolParameterHeader struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	TenantID     uuid.UUID
	ConnectionID uuid.UUID
	ToolName     string
	HeaderName   string
	ArgumentPath []string
	Required     bool
	CreatedAt    time.Time
}

// MCPToolHeaderSnapshot contains the complete parameter-header metadata observed for one tool.
// An empty Headers slice explicitly clears previously discovered metadata for ToolName.
type MCPToolHeaderSnapshot struct {
	ToolName string
	Headers  []MCPToolParameterHeader
}

// ValidateMCPToolParameterHeaders validates metadata before an atomic replacement is attempted.
func ValidateMCPToolParameterHeaders(headers []MCPToolParameterHeader) error {
	seen := make(map[string]struct{}, len(headers))
	for i, header := range headers {
		if strings.TrimSpace(header.ToolName) == "" || strings.TrimSpace(header.HeaderName) == "" || len(header.ArgumentPath) == 0 {
			return fmt.Errorf("%w at index %d", ErrInvalidMCPToolParameterHeader, i)
		}
		for _, component := range header.ArgumentPath {
			if strings.TrimSpace(component) == "" {
				return fmt.Errorf("%w at index %d", ErrInvalidMCPToolParameterHeader, i)
			}
		}
		key := header.ToolName + "\x00" + strings.ToLower(header.HeaderName)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: duplicate %s/%s", ErrInvalidMCPToolParameterHeader, header.ToolName, header.HeaderName)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// ValidateMCPToolHeaderSnapshots validates a page of complete per-tool metadata snapshots.
func ValidateMCPToolHeaderSnapshots(snapshots []MCPToolHeaderSnapshot) error {
	seenTools := make(map[string]struct{}, len(snapshots))
	for i, snapshot := range snapshots {
		if strings.TrimSpace(snapshot.ToolName) == "" {
			return fmt.Errorf("%w: empty tool at snapshot %d", ErrInvalidMCPToolParameterHeader, i)
		}
		if _, exists := seenTools[snapshot.ToolName]; exists {
			return fmt.Errorf("%w: duplicate tool %s", ErrInvalidMCPToolParameterHeader, snapshot.ToolName)
		}
		seenTools[snapshot.ToolName] = struct{}{}
		for j := range snapshot.Headers {
			toolName := snapshot.Headers[j].ToolName
			if toolName != "" && toolName != snapshot.ToolName {
				return fmt.Errorf("%w: tool mismatch at snapshot %d header %d", ErrInvalidMCPToolParameterHeader, i, j)
			}
			snapshot.Headers[j].ToolName = snapshot.ToolName
		}
		if err := ValidateMCPToolParameterHeaders(snapshot.Headers); err != nil {
			return err
		}
	}
	return nil
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
