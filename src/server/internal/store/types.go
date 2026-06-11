// Package store is the persistence layer. It deliberately uses hand-written SQL over pgx rather than
// an ORM: the schema is small and CRUD-shaped, and for a credential vault the exact SQL that touches
// the secret and audit tables should be visible and auditable. Every query is scoped to a user id
// passed explicitly (the Go equivalent of the C# per-user query filter); a handful of methods take
// an explicit owner id for the anonymous OAuth callback, which has no ambient caller.
//
// The structs below map 1:1 to the existing `vault` schema tables that the .NET service created;
// column names and types are unchanged so the two services can read each other's data.
package store

import (
	"time"

	"github.com/google/uuid"
)

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
