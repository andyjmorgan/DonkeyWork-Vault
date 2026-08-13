package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/crypto"
	"donkeywork.dev/vault-server/internal/mcp"
	"donkeywork.dev/vault-server/internal/store"
)

const mcpProtocolVersion = "2026-07-28"

var mcpSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,99}$`)

// MCPConnectionParams is the editable configuration for one modern MCP upstream.
type MCPConnectionParams struct {
	ID          uuid.UUID
	Slug        string
	Name        string
	Description *string
	UpstreamURL string
	AuthMode    string
	AuditMode   string
	Enabled     bool
}

// MCPResolvedConnection is an authorized upstream request configuration. Headers contain decrypted
// values and must never be logged or persisted in audit records.
type MCPResolvedConnection struct {
	Connection store.MCPConnection
	Headers    http.Header
	Policy     mcp.Policy
}

// MCPService manages MCP connections, grants, policies, upstream headers, and audit persistence.
type MCPService struct {
	store  store.Store
	cipher crypto.Cipher
}

// NewMCPService builds the MCP gateway domain service.
func NewMCPService(s store.Store, cipher crypto.Cipher) *MCPService {
	return &MCPService{store: s, cipher: cipher}
}

// UpsertConnection validates and creates or updates an owner-scoped connection.
func (s *MCPService) UpsertConnection(ctx context.Context, p MCPConnectionParams) (*store.MCPConnection, error) {
	caller := contracts.CallerFrom(ctx)
	p.Slug = strings.TrimSpace(strings.ToLower(p.Slug))
	p.Name = strings.TrimSpace(p.Name)
	p.AuthMode = strings.TrimSpace(strings.ToLower(p.AuthMode))
	p.AuditMode = strings.TrimSpace(strings.ToLower(p.AuditMode))
	if !mcpSlugPattern.MatchString(p.Slug) {
		return nil, ValidationError{"slug must contain only lowercase letters, digits, '-' or '_'."}
	}
	if p.Name == "" {
		return nil, ValidationError{"name is required."}
	}
	u, err := url.Parse(p.UpstreamURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, ValidationError{"upstreamUrl must be an absolute HTTPS URL without credentials or a fragment."}
	}
	if !slices.Contains([]string{"none", "headers", "oauth"}, p.AuthMode) {
		return nil, ValidationError{"authMode must be 'none', 'headers', or 'oauth'."}
	}
	if p.AuditMode == "" {
		p.AuditMode = "redacted"
	}
	if !slices.Contains([]string{"metadata", "redacted"}, p.AuditMode) {
		return nil, ValidationError{"auditMode must be 'metadata' or 'redacted'."}
	}
	entity := &store.MCPConnection{
		ID: p.ID, UserID: caller.UserID, TenantID: caller.TenantID, Slug: p.Slug,
		Name: p.Name, Description: p.Description, UpstreamURL: u.String(), AuthMode: p.AuthMode,
		AuditMode: p.AuditMode, ProtocolVersion: mcpProtocolVersion, Enabled: p.Enabled,
	}
	if entity.ID == uuid.Nil {
		if err := s.store.InsertMCPConnection(ctx, entity); err != nil {
			return nil, err
		}
		return entity, nil
	}
	updated, err := s.store.UpdateMCPConnection(ctx, entity)
	if err != nil {
		return nil, err
	}
	if !updated {
		return nil, nil
	}
	return entity, nil
}

// ListConnections returns the caller's MCP connections.
func (s *MCPService) ListConnections(ctx context.Context) ([]store.MCPConnection, error) {
	return s.store.ListMCPConnections(ctx, contracts.CallerFrom(ctx).UserID)
}

// GetConnection returns one caller-owned MCP connection.
func (s *MCPService) GetConnection(ctx context.Context, id uuid.UUID) (*store.MCPConnection, error) {
	return s.store.GetMCPConnectionByID(ctx, contracts.CallerFrom(ctx).UserID, id)
}

// DeleteConnection removes one caller-owned MCP connection and its mutable configuration.
func (s *MCPService) DeleteConnection(ctx context.Context, id uuid.UUID) (bool, error) {
	return s.store.DeleteMCPConnection(ctx, contracts.CallerFrom(ctx).UserID, id)
}

// Grant authorizes a caller-owned access key to use a caller-owned MCP connection.
func (s *MCPService) Grant(ctx context.Context, connectionID, accessKeyID uuid.UUID) (*store.MCPConnectionGrant, error) {
	caller := contracts.CallerFrom(ctx)
	if connection, err := s.store.GetMCPConnectionByID(ctx, caller.UserID, connectionID); err != nil || connection == nil {
		return nil, err
	}
	if key, err := s.store.GetAccessKeyByID(ctx, caller.UserID, accessKeyID); err != nil || key == nil {
		return nil, err
	}
	g := &store.MCPConnectionGrant{UserID: caller.UserID, TenantID: caller.TenantID, ConnectionID: connectionID, AccessKeyID: accessKeyID}
	if err := s.store.InsertMCPConnectionGrant(ctx, g); err != nil {
		return nil, err
	}
	return g, nil
}

// ListGrants lists a caller-owned connection's access-key grants.
func (s *MCPService) ListGrants(ctx context.Context, connectionID uuid.UUID) ([]store.MCPConnectionGrant, error) {
	return s.store.ListMCPConnectionGrants(ctx, contracts.CallerFrom(ctx).UserID, connectionID)
}

// DeleteGrant revokes a caller-owned grant.
func (s *MCPService) DeleteGrant(ctx context.Context, id uuid.UUID) (bool, error) {
	return s.store.DeleteMCPConnectionGrant(ctx, contracts.CallerFrom(ctx).UserID, id)
}

// BindHeader maps one existing encrypted API credential onto an upstream request header.
func (s *MCPService) BindHeader(ctx context.Context, connectionID, credentialID uuid.UUID, headerName *string) (*store.MCPHeaderBinding, error) {
	caller := contracts.CallerFrom(ctx)
	if connection, err := s.store.GetMCPConnectionByID(ctx, caller.UserID, connectionID); err != nil || connection == nil {
		return nil, err
	}
	if credential, err := s.store.GetAPIKeyByID(ctx, caller.UserID, credentialID); err != nil || credential == nil {
		return nil, err
	}
	if headerName != nil && !validHTTPFieldName(*headerName) {
		return nil, ValidationError{"headerName is not a valid HTTP field name."}
	}
	if headerName != nil && !allowedMCPUpstreamHeader(*headerName) {
		return nil, ValidationError{"headerName is reserved by the MCP gateway."}
	}
	b := &store.MCPHeaderBinding{UserID: caller.UserID, TenantID: caller.TenantID, ConnectionID: connectionID, CredentialID: credentialID, HeaderName: headerName}
	if err := s.store.InsertMCPHeaderBinding(ctx, b); err != nil {
		return nil, err
	}
	return b, nil
}

// ListHeaderBindings returns metadata-only upstream header bindings.
func (s *MCPService) ListHeaderBindings(ctx context.Context, connectionID uuid.UUID) ([]store.MCPHeaderBinding, error) {
	return s.store.ListMCPHeaderBindings(ctx, contracts.CallerFrom(ctx).UserID, connectionID)
}

// DeleteHeaderBinding removes an upstream header binding.
func (s *MCPService) DeleteHeaderBinding(ctx context.Context, id uuid.UUID) (bool, error) {
	return s.store.DeleteMCPHeaderBinding(ctx, contracts.CallerFrom(ctx).UserID, id)
}

// PutPolicy creates or replaces an exact method/tool policy rule.
func (s *MCPService) PutPolicy(ctx context.Context, connectionID uuid.UUID, method, toolName string, allow bool) (*store.MCPToolPolicy, error) {
	caller := contracts.CallerFrom(ctx)
	if connection, err := s.store.GetMCPConnectionByID(ctx, caller.UserID, connectionID); err != nil || connection == nil {
		return nil, err
	}
	method, toolName = strings.TrimSpace(method), strings.TrimSpace(toolName)
	if method == "" || (toolName != "" && method != "tools/call") {
		return nil, ValidationError{"method is required and toolName is valid only for tools/call."}
	}
	p := &store.MCPToolPolicy{UserID: caller.UserID, TenantID: caller.TenantID, ConnectionID: connectionID, Method: method, ToolName: toolName, Allow: allow}
	if err := s.store.UpsertMCPToolPolicy(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// ListPolicies returns a connection's exact policy rules.
func (s *MCPService) ListPolicies(ctx context.Context, connectionID uuid.UUID) ([]store.MCPToolPolicy, error) {
	return s.store.ListMCPToolPolicies(ctx, contracts.CallerFrom(ctx).UserID, connectionID)
}

// DeletePolicy removes one exact policy rule.
func (s *MCPService) DeletePolicy(ctx context.Context, id uuid.UUID) (bool, error) {
	return s.store.DeleteMCPToolPolicy(ctx, contracts.CallerFrom(ctx).UserID, id)
}

// ResolveProxy verifies the key-to-connection grant and decrypts upstream static headers.
func (s *MCPService) ResolveProxy(ctx context.Context, slug string, accessKeyID uuid.UUID) (*MCPResolvedConnection, error) {
	caller := contracts.CallerFrom(ctx)
	connection, err := s.store.GetMCPConnectionBySlug(ctx, caller.UserID, slug)
	if err != nil || connection == nil || !connection.Enabled {
		return nil, err
	}
	granted, err := s.store.HasMCPConnectionGrant(ctx, accessKeyID, connection.ID)
	if err != nil {
		return nil, err
	}
	if !granted {
		return nil, errors.New("MCP connection grant required")
	}
	return s.resolveConnection(ctx, connection)
}

// ResolveProbe loads a caller-owned connection with its upstream authentication but requires no
// access-key grant because probing is an authenticated administrative action.
func (s *MCPService) ResolveProbe(ctx context.Context, connectionID uuid.UUID) (*MCPResolvedConnection, error) {
	caller := contracts.CallerFrom(ctx)
	connection, err := s.store.GetMCPConnectionByID(ctx, caller.UserID, connectionID)
	if err != nil || connection == nil {
		return nil, err
	}
	return s.resolveConnection(ctx, connection)
}

func (s *MCPService) resolveConnection(ctx context.Context, connection *store.MCPConnection) (*MCPResolvedConnection, error) {
	caller := contracts.CallerFrom(ctx)
	resolved := &MCPResolvedConnection{Connection: *connection, Headers: make(http.Header), Policy: mcp.Policy{
		Methods: mcp.AllowRule{Default: mcp.DefaultAllow}, Tools: mcp.AllowRule{Default: mcp.DefaultAllow},
	}}
	bindings, err := s.store.ListMCPHeaderBindings(ctx, caller.UserID, connection.ID)
	if err != nil {
		return nil, err
	}
	for _, binding := range bindings {
		credential, err := s.store.GetAPIKeyByID(ctx, caller.UserID, binding.CredentialID)
		if err != nil {
			return nil, err
		}
		if credential == nil {
			return nil, fmt.Errorf("MCP header credential %s not found", binding.CredentialID)
		}
		secret, err := s.cipher.DecryptToString(credential.FieldsCipher)
		if err != nil {
			return nil, err
		}
		name, value := AssembleHeader(contracts.CredentialKindFromWire(credential.Kind), deref(credential.HeaderName), deref(credential.Prefix), deref(credential.Username), secret)
		if binding.HeaderName != nil {
			name = *binding.HeaderName
		}
		if !validHTTPFieldName(name) || !allowedMCPUpstreamHeader(name) || strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("stored MCP header binding is invalid")
		}
		resolved.Headers.Add(name, value)
	}
	policies, err := s.store.ListMCPToolPolicies(ctx, caller.UserID, connection.ID)
	if err != nil {
		return nil, err
	}
	for _, policy := range policies {
		if policy.ToolName != "" {
			if policy.Allow {
				resolved.Policy.Tools.Default = mcp.DefaultDeny
			}
			appendRule(&resolved.Policy.Tools, policy.ToolName, policy.Allow)
			continue
		}
		if policy.Allow {
			resolved.Policy.Methods.Default = mcp.DefaultDeny
		}
		appendRule(&resolved.Policy.Methods, policy.Method, policy.Allow)
	}
	return resolved, nil
}

// Store exposes the MCP-specific persistence operations to the protocol-aware HTTP gateway.
func (s *MCPService) Store() store.Store { return s.store }

func appendRule(rule *mcp.AllowRule, value string, allow bool) {
	if allow {
		rule.Allow = append(rule.Allow, value)
	} else {
		rule.Deny = append(rule.Deny, value)
	}
}

func validHTTPFieldName(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range []byte(value) {
		if char < 'a' || char > 'z' {
			if char < 'A' || char > 'Z' {
				if char < '0' || char > '9' {
					if !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(char)) {
						return false
					}
				}
			}
		}
	}
	return true
}

func allowedMCPUpstreamHeader(value string) bool {
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "mcp-") {
		return false
	}
	switch lower {
	case "accept", "content-type", "host", "cookie", "set-cookie", "connection", "keep-alive",
		"proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return false
	default:
		return true
	}
}
