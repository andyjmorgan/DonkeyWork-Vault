package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

const mcpConnectionCols = `id, user_id, tenant_id, slug, name, description, upstream_url, auth_mode, audit_mode, protocol_version, upstream_protocol_mode, legacy_protocol_version, protocol_era, probe_status, probe_checked_at, probe_error, probe_detail, supported_versions, server_name, server_version, enabled, created_at, updated_at`

func scanMCPConnection(row pgx.Row) (*MCPConnection, error) {
	var c MCPConnection
	err := row.Scan(&c.ID, &c.UserID, &c.TenantID, &c.Slug, &c.Name, &c.Description,
		&c.UpstreamURL, &c.AuthMode, &c.AuditMode, &c.ProtocolVersion, &c.UpstreamProtocolMode,
		&c.LegacyProtocolVersion, &c.ProtocolEra,
		&c.ProbeStatus, &c.ProbeCheckedAt, &c.ProbeError, &c.ProbeDetail, &c.SupportedVersions,
		&c.ServerName, &c.ServerVersion, &c.Enabled,
		&c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// InsertMCPConnection persists an MCP connection and back-fills generated fields.
func (p *Postgres) InsertMCPConnection(ctx context.Context, c *MCPConnection) error {
	if c.UpstreamProtocolMode == "" {
		c.UpstreamProtocolMode = "modern_2026_07"
	}
	if c.LegacyProtocolVersion == "" {
		c.LegacyProtocolVersion = "2025-06-18"
	}
	return p.pool.QueryRow(ctx, `
		INSERT INTO vault.mcp_connections
			(user_id, tenant_id, slug, name, description, upstream_url, auth_mode, audit_mode, protocol_version, upstream_protocol_mode, legacy_protocol_version, enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id, created_at, protocol_era, probe_status`, c.UserID, c.TenantID, c.Slug, c.Name, c.Description,
		c.UpstreamURL, c.AuthMode, c.AuditMode, c.ProtocolVersion, c.UpstreamProtocolMode, c.LegacyProtocolVersion, c.Enabled).
		Scan(&c.ID, &c.CreatedAt, &c.ProtocolEra, &c.ProbeStatus)
}

// UpdateMCPConnection updates mutable fields when the connection belongs to the supplied owner.
func (p *Postgres) UpdateMCPConnection(ctx context.Context, c *MCPConnection) (bool, error) {
	err := p.pool.QueryRow(ctx, `
		UPDATE vault.mcp_connections SET slug=$3, name=$4, description=$5, upstream_url=$6,
			auth_mode=$7, audit_mode=$8, protocol_version=$9, upstream_protocol_mode=$10,
			legacy_protocol_version=$11, enabled=$12, updated_at=now()
		WHERE user_id=$1 AND id=$2
		RETURNING updated_at, protocol_era, probe_status, probe_checked_at, probe_error, probe_detail,
			supported_versions, server_name, server_version`, c.UserID, c.ID, c.Slug, c.Name,
		c.Description, c.UpstreamURL, c.AuthMode, c.AuditMode, c.ProtocolVersion, c.UpstreamProtocolMode,
		c.LegacyProtocolVersion, c.Enabled).
		Scan(&c.UpdatedAt, &c.ProtocolEra, &c.ProbeStatus, &c.ProbeCheckedAt, &c.ProbeError,
			&c.ProbeDetail, &c.SupportedVersions, &c.ServerName, &c.ServerVersion)
	if noRows(err) {
		return false, nil
	}
	return err == nil, err
}

// ListMCPConnections returns a user's MCP connections ordered by name.
func (p *Postgres) ListMCPConnections(ctx context.Context, userID uuid.UUID) ([]MCPConnection, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+mcpConnectionCols+` FROM vault.mcp_connections WHERE user_id=$1 ORDER BY name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MCPConnection
	for rows.Next() {
		c, err := scanMCPConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// GetMCPConnectionByID returns an owner-scoped MCP connection by ID.
func (p *Postgres) GetMCPConnectionByID(ctx context.Context, userID, id uuid.UUID) (*MCPConnection, error) {
	c, err := scanMCPConnection(p.pool.QueryRow(ctx, `SELECT `+mcpConnectionCols+` FROM vault.mcp_connections WHERE user_id=$1 AND id=$2`, userID, id))
	if noRows(err) {
		return nil, nil
	}
	return c, err
}

// GetMCPConnectionBySlug returns an owner-scoped MCP connection by slug.
func (p *Postgres) GetMCPConnectionBySlug(ctx context.Context, userID uuid.UUID, slug string) (*MCPConnection, error) {
	c, err := scanMCPConnection(p.pool.QueryRow(ctx, `SELECT `+mcpConnectionCols+` FROM vault.mcp_connections WHERE user_id=$1 AND slug=$2`, userID, slug))
	if noRows(err) {
		return nil, nil
	}
	return c, err
}

// DeleteMCPConnection deletes an owner-scoped MCP connection and its dependent configuration.
func (p *Postgres) DeleteMCPConnection(ctx context.Context, userID, id uuid.UUID) (bool, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM vault.mcp_connections WHERE user_id=$1 AND id=$2`, userID, id)
	return tag.RowsAffected() > 0, err
}

// RecordMCPProtocolProbe records probe-owned fields without overwriting editable connection config.
func (p *Postgres) RecordMCPProtocolProbe(ctx context.Context, result *MCPProtocolProbeResult) (bool, error) {
	if result == nil {
		return false, ErrInvalidMCPProtocolProbe
	}
	if err := ValidateMCPProtocolProbe(*result); err != nil {
		return false, err
	}
	tag, err := p.pool.Exec(ctx, `
		UPDATE vault.mcp_connections SET protocol_era=$4, probe_status=$5, probe_checked_at=$6,
			probe_error=$7, probe_detail=$8, supported_versions=$9, server_name=$10, server_version=$11
		WHERE id=$1 AND user_id=$2 AND tenant_id=$3`, result.ConnectionID, result.UserID,
		result.TenantID, result.ProtocolEra, result.Status, result.CheckedAt, result.Error,
		result.Detail, nonNilStrings(result.SupportedVersions), result.ServerName, result.ServerVersion)
	return tag.RowsAffected() > 0, err
}

const mcpGrantCols = `id, user_id, tenant_id, connection_id, access_key_id, created_at`

// InsertMCPConnectionGrant inserts a grant only when the key and connection share its owner.
func (p *Postgres) InsertMCPConnectionGrant(ctx context.Context, g *MCPConnectionGrant) error {
	err := p.pool.QueryRow(ctx, `
		INSERT INTO vault.mcp_connection_grants (user_id, tenant_id, connection_id, access_key_id)
		SELECT $1,$2,c.id,k.id FROM vault.mcp_connections c JOIN vault.access_keys k
			ON k.id=$4 AND k.user_id=$1 AND k.tenant_id=$2
		WHERE c.id=$3 AND c.user_id=$1 AND c.tenant_id=$2
		RETURNING id, created_at`, g.UserID, g.TenantID, g.ConnectionID, g.AccessKeyID).
		Scan(&g.ID, &g.CreatedAt)
	if noRows(err) {
		return ErrOwnershipMismatch
	}
	return err
}

// ListMCPConnectionGrants returns grants for one owner-scoped connection.
func (p *Postgres) ListMCPConnectionGrants(ctx context.Context, userID, connectionID uuid.UUID) ([]MCPConnectionGrant, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+mcpGrantCols+` FROM vault.mcp_connection_grants WHERE user_id=$1 AND connection_id=$2 ORDER BY created_at`, userID, connectionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MCPConnectionGrant
	for rows.Next() {
		var g MCPConnectionGrant
		if err := rows.Scan(&g.ID, &g.UserID, &g.TenantID, &g.ConnectionID, &g.AccessKeyID, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// HasMCPConnectionGrant reports whether an access key may use a connection.
func (p *Postgres) HasMCPConnectionGrant(ctx context.Context, accessKeyID, connectionID uuid.UUID) (bool, error) {
	var exists bool
	err := p.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vault.mcp_connection_grants WHERE access_key_id=$1 AND connection_id=$2)`, accessKeyID, connectionID).Scan(&exists)
	return exists, err
}

// DeleteMCPConnectionGrant removes an owner-scoped connection grant.
func (p *Postgres) DeleteMCPConnectionGrant(ctx context.Context, userID, id uuid.UUID) (bool, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM vault.mcp_connection_grants WHERE user_id=$1 AND id=$2`, userID, id)
	return tag.RowsAffected() > 0, err
}

const mcpHeaderCols = `id, user_id, tenant_id, connection_id, credential_id, header_name, created_at`

// InsertMCPHeaderBinding binds an existing credential owned by the connection owner.
func (p *Postgres) InsertMCPHeaderBinding(ctx context.Context, b *MCPHeaderBinding) error {
	err := p.pool.QueryRow(ctx, `
		INSERT INTO vault.mcp_header_bindings (user_id, tenant_id, connection_id, credential_id, header_name)
		SELECT $1,$2,c.id,k.id,$5 FROM vault.mcp_connections c JOIN vault.api_keys k
			ON k.id=$4 AND k.user_id=$1 AND k.tenant_id=$2
		WHERE c.id=$3 AND c.user_id=$1 AND c.tenant_id=$2
		RETURNING id, created_at`, b.UserID, b.TenantID, b.ConnectionID, b.CredentialID, b.HeaderName).
		Scan(&b.ID, &b.CreatedAt)
	if noRows(err) {
		return ErrOwnershipMismatch
	}
	return err
}

// ListMCPHeaderBindings returns header bindings for one owner-scoped connection.
func (p *Postgres) ListMCPHeaderBindings(ctx context.Context, userID, connectionID uuid.UUID) ([]MCPHeaderBinding, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+mcpHeaderCols+` FROM vault.mcp_header_bindings WHERE user_id=$1 AND connection_id=$2 ORDER BY created_at`, userID, connectionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MCPHeaderBinding
	for rows.Next() {
		var b MCPHeaderBinding
		if err := rows.Scan(&b.ID, &b.UserID, &b.TenantID, &b.ConnectionID, &b.CredentialID, &b.HeaderName, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DeleteMCPHeaderBinding removes an owner-scoped header binding.
func (p *Postgres) DeleteMCPHeaderBinding(ctx context.Context, userID, id uuid.UUID) (bool, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM vault.mcp_header_bindings WHERE user_id=$1 AND id=$2`, userID, id)
	return tag.RowsAffected() > 0, err
}

const mcpToolPolicyCols = `id, user_id, tenant_id, connection_id, method, tool_name, allow, created_at, updated_at`

// UpsertMCPToolPolicy creates or replaces the decision for one method and tool selector.
func (p *Postgres) UpsertMCPToolPolicy(ctx context.Context, policy *MCPToolPolicy) error {
	err := p.pool.QueryRow(ctx, `
		INSERT INTO vault.mcp_tool_policies (user_id, tenant_id, connection_id, method, tool_name, allow)
		SELECT $1,$2,c.id,$4,$5,$6 FROM vault.mcp_connections c
		WHERE c.id=$3 AND c.user_id=$1 AND c.tenant_id=$2
		ON CONFLICT (connection_id, method, tool_name) DO UPDATE SET allow=excluded.allow, updated_at=now()
		RETURNING id, created_at, updated_at`, policy.UserID, policy.TenantID, policy.ConnectionID,
		policy.Method, policy.ToolName, policy.Allow).Scan(&policy.ID, &policy.CreatedAt, &policy.UpdatedAt)
	if noRows(err) {
		return ErrOwnershipMismatch
	}
	return err
}

// ListMCPToolPolicies returns policies for one owner-scoped connection.
func (p *Postgres) ListMCPToolPolicies(ctx context.Context, userID, connectionID uuid.UUID) ([]MCPToolPolicy, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+mcpToolPolicyCols+` FROM vault.mcp_tool_policies WHERE user_id=$1 AND connection_id=$2 ORDER BY method, tool_name`, userID, connectionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MCPToolPolicy
	for rows.Next() {
		var policy MCPToolPolicy
		if err := rows.Scan(&policy.ID, &policy.UserID, &policy.TenantID, &policy.ConnectionID,
			&policy.Method, &policy.ToolName, &policy.Allow, &policy.CreatedAt, &policy.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, policy)
	}
	return out, rows.Err()
}

// DeleteMCPToolPolicy removes an owner-scoped tool policy.
func (p *Postgres) DeleteMCPToolPolicy(ctx context.Context, userID, id uuid.UUID) (bool, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM vault.mcp_tool_policies WHERE user_id=$1 AND id=$2`, userID, id)
	return tag.RowsAffected() > 0, err
}

// ReplaceMCPToolParameterHeaders atomically replaces a connection's discovered parameter-header metadata.
func (p *Postgres) ReplaceMCPToolParameterHeaders(ctx context.Context, userID, tenantID, connectionID uuid.UUID, headers []MCPToolParameterHeader) error {
	if err := ValidateMCPToolParameterHeaders(headers); err != nil {
		return err
	}
	for i := range headers {
		if headers[i].UserID != uuid.Nil && headers[i].UserID != userID ||
			headers[i].TenantID != uuid.Nil && headers[i].TenantID != tenantID ||
			headers[i].ConnectionID != uuid.Nil && headers[i].ConnectionID != connectionID {
			return ErrOwnershipMismatch
		}
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err //coverage:ignore a live pool beginning this short transaction has no deterministic unit-test failure seam.
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var owns bool
	if err := tx.QueryRow(ctx, `SELECT true FROM vault.mcp_connections WHERE id=$1 AND user_id=$2 AND tenant_id=$3 FOR UPDATE`, connectionID, userID, tenantID).Scan(&owns); err != nil {
		if noRows(err) {
			return ErrOwnershipMismatch
		}
		return err //coverage:ignore the fixed SELECT can only fail after the pool/transaction becomes unusable.
	}
	if _, err := tx.Exec(ctx, `DELETE FROM vault.mcp_tool_parameter_headers WHERE connection_id=$1`, connectionID); err != nil {
		return err //coverage:ignore the fixed DELETE can only fail after the validated transaction becomes unusable.
	}
	for i := range headers {
		header := &headers[i]
		if err := tx.QueryRow(ctx, `
			INSERT INTO vault.mcp_tool_parameter_headers
				(user_id, tenant_id, connection_id, tool_name, header_name, argument_path, required)
			VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, created_at`, userID, tenantID,
			connectionID, header.ToolName, header.HeaderName, header.ArgumentPath, header.Required).
			Scan(&header.ID, &header.CreatedAt); err != nil {
			return err
		}
		header.UserID, header.TenantID, header.ConnectionID = userID, tenantID, connectionID
	}
	return tx.Commit(ctx)
}

// UpsertMCPToolParameterHeaders atomically replaces metadata for explicitly observed tools.
func (p *Postgres) UpsertMCPToolParameterHeaders(ctx context.Context, userID, tenantID, connectionID uuid.UUID, snapshots []MCPToolHeaderSnapshot) error {
	if err := ValidateMCPToolHeaderSnapshots(snapshots); err != nil {
		return err
	}
	for i := range snapshots {
		for j := range snapshots[i].Headers {
			header := &snapshots[i].Headers[j]
			if header.UserID != uuid.Nil && header.UserID != userID ||
				header.TenantID != uuid.Nil && header.TenantID != tenantID ||
				header.ConnectionID != uuid.Nil && header.ConnectionID != connectionID {
				return ErrOwnershipMismatch
			}
		}
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err //coverage:ignore a live pool beginning this short transaction has no deterministic unit-test failure seam.
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var owns bool
	if err := tx.QueryRow(ctx, `SELECT true FROM vault.mcp_connections WHERE id=$1 AND user_id=$2 AND tenant_id=$3 FOR UPDATE`, connectionID, userID, tenantID).Scan(&owns); err != nil {
		if noRows(err) {
			return ErrOwnershipMismatch
		}
		return err //coverage:ignore the fixed SELECT can only fail after the pool/transaction becomes unusable.
	}
	for i := range snapshots {
		snapshot := &snapshots[i]
		if _, err := tx.Exec(ctx, `DELETE FROM vault.mcp_tool_parameter_headers WHERE connection_id=$1 AND tool_name=$2`, connectionID, snapshot.ToolName); err != nil {
			return err //coverage:ignore the fixed DELETE can only fail after the validated transaction becomes unusable.
		}
		for j := range snapshot.Headers {
			header := &snapshot.Headers[j]
			header.ToolName = snapshot.ToolName
			if err := tx.QueryRow(ctx, `
				INSERT INTO vault.mcp_tool_parameter_headers
					(user_id, tenant_id, connection_id, tool_name, header_name, argument_path, required)
				VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, created_at`, userID, tenantID,
				connectionID, header.ToolName, header.HeaderName, header.ArgumentPath, header.Required).
				Scan(&header.ID, &header.CreatedAt); err != nil {
				return err
			}
			header.UserID, header.TenantID, header.ConnectionID = userID, tenantID, connectionID
		}
	}
	return tx.Commit(ctx)
}

// ListMCPToolParameterHeaders returns discovered parameter headers for one owner-scoped tool.
func (p *Postgres) ListMCPToolParameterHeaders(ctx context.Context, userID, connectionID uuid.UUID, toolName string) ([]MCPToolParameterHeader, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, user_id, tenant_id, connection_id, tool_name, header_name, argument_path, required, created_at
		FROM vault.mcp_tool_parameter_headers
		WHERE user_id=$1 AND connection_id=$2 AND tool_name=$3 ORDER BY lower(header_name)`, userID, connectionID, toolName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MCPToolParameterHeader
	for rows.Next() {
		var header MCPToolParameterHeader
		if err := rows.Scan(&header.ID, &header.UserID, &header.TenantID, &header.ConnectionID,
			&header.ToolName, &header.HeaderName, &header.ArgumentPath, &header.Required, &header.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, header)
	}
	return out, rows.Err()
}

const mcpOAuthCols = `id, user_id, tenant_id, connection_id, issuer_url, authorization_endpoint, token_endpoint, resource, token_type, token_auth_method, client_id_cipher, client_secret_cipher, access_token_cipher, refresh_token_cipher, scopes, expires_at, last_refreshed_at, created_at, updated_at`

func scanMCPOAuthAuthorization(row pgx.Row) (*MCPOAuthAuthorization, error) {
	var a MCPOAuthAuthorization
	err := row.Scan(&a.ID, &a.UserID, &a.TenantID, &a.ConnectionID, &a.IssuerURL,
		&a.AuthorizationEndpoint, &a.TokenEndpoint, &a.Resource, &a.TokenType, &a.TokenAuthMethod, &a.ClientIDCipher,
		&a.ClientSecretCipher, &a.AccessTokenCipher, &a.RefreshTokenCipher, &a.Scopes,
		&a.ExpiresAt, &a.LastRefreshedAt, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// InsertMCPOAuthAuthorization stores a connection-bound OAuth client and token set.
func (p *Postgres) InsertMCPOAuthAuthorization(ctx context.Context, a *MCPOAuthAuthorization) error {
	err := p.pool.QueryRow(ctx, `
		INSERT INTO vault.mcp_oauth_authorizations (user_id, tenant_id, connection_id, issuer_url,
			authorization_endpoint, token_endpoint, resource, token_type, token_auth_method, client_id_cipher,
			client_secret_cipher, access_token_cipher, refresh_token_cipher, scopes, expires_at, last_refreshed_at)
		SELECT $1,$2,c.id,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16 FROM vault.mcp_connections c
		WHERE c.id=$3 AND c.user_id=$1 AND c.tenant_id=$2 RETURNING id, created_at`,
		a.UserID, a.TenantID, a.ConnectionID, a.IssuerURL, a.AuthorizationEndpoint, a.TokenEndpoint,
		a.Resource, a.TokenType, a.TokenAuthMethod, a.ClientIDCipher, a.ClientSecretCipher, a.AccessTokenCipher,
		a.RefreshTokenCipher, nonNilStrings(a.Scopes), a.ExpiresAt, a.LastRefreshedAt).Scan(&a.ID, &a.CreatedAt)
	if noRows(err) {
		return ErrOwnershipMismatch
	}
	return err
}

// UpdateMCPOAuthAuthorization updates the encrypted token set and discovery metadata.
func (p *Postgres) UpdateMCPOAuthAuthorization(ctx context.Context, a *MCPOAuthAuthorization) (bool, error) {
	err := p.pool.QueryRow(ctx, `
		UPDATE vault.mcp_oauth_authorizations SET issuer_url=$4, authorization_endpoint=$5,
			token_endpoint=$6, resource=$7, token_type=$8, token_auth_method=$9, client_id_cipher=$10,
			client_secret_cipher=$11, access_token_cipher=$12, refresh_token_cipher=$13,
			scopes=$14, expires_at=$15, last_refreshed_at=$16, updated_at=now()
		WHERE user_id=$1 AND id=$2 AND connection_id=$3 RETURNING updated_at`, a.UserID, a.ID,
		a.ConnectionID, a.IssuerURL, a.AuthorizationEndpoint, a.TokenEndpoint, a.Resource, a.TokenType,
		a.TokenAuthMethod, a.ClientIDCipher, a.ClientSecretCipher, a.AccessTokenCipher, a.RefreshTokenCipher, nonNilStrings(a.Scopes),
		a.ExpiresAt, a.LastRefreshedAt).Scan(&a.UpdatedAt)
	if noRows(err) {
		return false, nil
	}
	return err == nil, err
}

// GetMCPOAuthAuthorization returns the OAuth authorization for an owner-scoped connection.
func (p *Postgres) GetMCPOAuthAuthorization(ctx context.Context, userID, connectionID uuid.UUID) (*MCPOAuthAuthorization, error) {
	a, err := scanMCPOAuthAuthorization(p.pool.QueryRow(ctx, `SELECT `+mcpOAuthCols+` FROM vault.mcp_oauth_authorizations WHERE user_id=$1 AND connection_id=$2`, userID, connectionID))
	if noRows(err) {
		return nil, nil
	}
	return a, err
}

// DeleteMCPOAuthAuthorization deletes the OAuth authorization for an owner-scoped connection.
func (p *Postgres) DeleteMCPOAuthAuthorization(ctx context.Context, userID, connectionID uuid.UUID) (bool, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM vault.mcp_oauth_authorizations WHERE user_id=$1 AND connection_id=$2`, userID, connectionID)
	return tag.RowsAffected() > 0, err
}

// InsertMCPOAuthState atomically supersedes the prior state for a connection after verifying
// ownership. The connection uniqueness constraint serializes concurrent attempts across replicas.
func (p *Postgres) InsertMCPOAuthState(ctx context.Context, s *MCPOAuthState) error {
	err := p.pool.QueryRow(ctx, `
		INSERT INTO vault.mcp_oauth_states (state, connection_id, user_id, tenant_id, code_verifier,
			redirect_uri, resource, issuer_url, auth_endpoint, token_endpoint, token_auth_method,
			scopes, expires_at)
		SELECT $1,c.id,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13 FROM vault.mcp_connections c
		WHERE c.id=$2 AND c.user_id=$3 AND c.tenant_id=$4
		ON CONFLICT (connection_id) DO UPDATE SET
			state=EXCLUDED.state, user_id=EXCLUDED.user_id, tenant_id=EXCLUDED.tenant_id,
			code_verifier=EXCLUDED.code_verifier, redirect_uri=EXCLUDED.redirect_uri,
			resource=EXCLUDED.resource, issuer_url=EXCLUDED.issuer_url,
			auth_endpoint=EXCLUDED.auth_endpoint, token_endpoint=EXCLUDED.token_endpoint,
			token_auth_method=EXCLUDED.token_auth_method, scopes=EXCLUDED.scopes,
			expires_at=EXCLUDED.expires_at, created_at=EXCLUDED.created_at
		RETURNING created_at`, s.State,
		s.ConnectionID, s.UserID, s.TenantID, s.CodeVerifier, s.RedirectURI, s.Resource,
		s.IssuerURL, s.AuthEndpoint, s.TokenEndpoint, s.TokenAuthMethod, nonNilStrings(s.Scopes), s.ExpiresAt).
		Scan(&s.CreatedAt)
	if noRows(err) {
		return ErrOwnershipMismatch
	}
	return err
}

// GetMCPOAuthStateByState returns an OAuth state without consuming it.
func (p *Postgres) GetMCPOAuthStateByState(ctx context.Context, state string) (*MCPOAuthState, error) {
	var s MCPOAuthState
	err := p.pool.QueryRow(ctx, `
		SELECT state, connection_id, user_id, tenant_id, code_verifier, redirect_uri, resource,
			issuer_url, auth_endpoint, token_endpoint, token_auth_method, scopes, expires_at, created_at
		FROM vault.mcp_oauth_states WHERE state=$1`, state).
		Scan(&s.State, &s.ConnectionID, &s.UserID, &s.TenantID, &s.CodeVerifier, &s.RedirectURI,
			&s.Resource, &s.IssuerURL, &s.AuthEndpoint, &s.TokenEndpoint, &s.TokenAuthMethod,
			&s.Scopes, &s.ExpiresAt, &s.CreatedAt)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// ClaimMCPOAuthState atomically deletes and returns a state, preventing callback replay.
func (p *Postgres) ClaimMCPOAuthState(ctx context.Context, state string) (*MCPOAuthState, error) {
	var s MCPOAuthState
	err := p.pool.QueryRow(ctx, `
		DELETE FROM vault.mcp_oauth_states WHERE state=$1
		RETURNING state, connection_id, user_id, tenant_id, code_verifier, redirect_uri, resource,
			issuer_url, auth_endpoint, token_endpoint, token_auth_method, scopes, expires_at, created_at`, state).
		Scan(&s.State, &s.ConnectionID, &s.UserID, &s.TenantID, &s.CodeVerifier, &s.RedirectURI,
			&s.Resource, &s.IssuerURL, &s.AuthEndpoint, &s.TokenEndpoint, &s.TokenAuthMethod,
			&s.Scopes, &s.ExpiresAt, &s.CreatedAt)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// InsertMCPAuditExchange starts an HTTP-level MCP audit exchange.
func (p *Postgres) InsertMCPAuditExchange(ctx context.Context, e *MCPAuditExchange) error {
	return p.pool.QueryRow(ctx, `
		INSERT INTO vault.mcp_audit_exchanges (connection_id, user_id, tenant_id, access_key_id,
			eval_run_id, downstream_request_id, upstream_request_id, remote_address, user_agent,
			trace_id, error_class, http_method, protocol_version, outcome, started_at, completed_at,
			status_code, request_bytes, response_bytes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		RETURNING id`, e.ConnectionID, e.UserID, e.TenantID, e.AccessKeyID, e.EvalRunID,
		e.DownstreamRequestID, e.UpstreamRequestID, e.RemoteAddress, e.UserAgent, e.TraceID,
		e.ErrorClass, e.HTTPMethod, e.ProtocolVersion, e.Outcome, e.StartedAt, e.CompletedAt,
		e.StatusCode, e.RequestBytes, e.ResponseBytes).Scan(&e.ID)
}

// CompleteMCPAuditExchange records the final transport outcome and byte counts.
func (p *Postgres) CompleteMCPAuditExchange(ctx context.Context, e *MCPAuditExchange) (bool, error) {
	tag, err := p.pool.Exec(ctx, `
		UPDATE vault.mcp_audit_exchanges SET upstream_request_id=$4, error_class=$5, outcome=$6,
			completed_at=$7, status_code=$8, request_bytes=$9, response_bytes=$10
		WHERE id=$1 AND user_id=$2 AND tenant_id=$3`, e.ID, e.UserID, e.TenantID,
		e.UpstreamRequestID, e.ErrorClass, e.Outcome, e.CompletedAt, e.StatusCode,
		e.RequestBytes, e.ResponseBytes)
	return tag.RowsAffected() > 0, err
}

const mcpAuditMessageCols = `m.id, m.exchange_id, m.connection_id, m.user_id, m.tenant_id, m.sequence_no, m.observed_at, m.direction, m.message_kind, m.policy_decision, m.jsonrpc_id_type, m.jsonrpc_id_text, m.method, m.tool_name, m.policy_rule, m.result_type, m.subscription_id, m.error_code, m.request_state_digest, m.payload_redacted::text, m.payload_sha256, m.payload_bytes, m.payload_truncated, m.redaction_paths`

// InsertMCPAuditMessage stores one inspected JSON-RPC message.
func (p *Postgres) InsertMCPAuditMessage(ctx context.Context, m *MCPAuditMessage) error {
	err := p.pool.QueryRow(ctx, `
		INSERT INTO vault.mcp_audit_messages (exchange_id, connection_id, user_id, tenant_id,
			sequence_no, observed_at, direction, message_kind, policy_decision, jsonrpc_id_type,
			jsonrpc_id_text, method, tool_name, policy_rule, result_type, subscription_id, error_code,
			request_state_digest, payload_redacted, payload_sha256, payload_bytes, payload_truncated,
			redaction_paths)
		SELECT e.id,e.connection_id,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19::jsonb,$20,$21,$22,$23
		FROM vault.mcp_audit_exchanges e WHERE e.id=$1 AND e.connection_id=$2 AND e.user_id=$3 AND e.tenant_id=$4
		RETURNING id`, m.ExchangeID, m.ConnectionID, m.UserID, m.TenantID, m.SequenceNo,
		m.ObservedAt, m.Direction, m.MessageKind, m.PolicyDecision, m.JSONRPCIDType,
		m.JSONRPCIDText, m.Method, m.ToolName, m.PolicyRule, m.ResultType, m.SubscriptionID,
		m.ErrorCode, m.RequestStateDigest, m.PayloadRedacted, m.PayloadSHA256, m.PayloadBytes,
		m.PayloadTruncated, nonNilStrings(m.RedactionPaths)).Scan(&m.ID)
	if noRows(err) {
		return ErrOwnershipMismatch
	}
	return err
}

func scanMCPAuditMessage(row pgx.Row) (*MCPAuditMessage, error) {
	var m MCPAuditMessage
	err := row.Scan(&m.ID, &m.ExchangeID, &m.ConnectionID, &m.UserID, &m.TenantID,
		&m.SequenceNo, &m.ObservedAt, &m.Direction, &m.MessageKind, &m.PolicyDecision,
		&m.JSONRPCIDType, &m.JSONRPCIDText, &m.Method, &m.ToolName, &m.PolicyRule,
		&m.ResultType, &m.SubscriptionID, &m.ErrorCode, &m.RequestStateDigest,
		&m.PayloadRedacted, &m.PayloadSHA256, &m.PayloadBytes, &m.PayloadTruncated,
		&m.RedactionPaths)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// QueryMCPAudit returns an owner-scoped page of inspected messages and the matching total.
func (p *Postgres) QueryMCPAudit(ctx context.Context, f MCPAuditFilter) ([]MCPAuditMessage, int, error) {
	where := ` WHERE m.user_id=$1 AND m.tenant_id=$2`
	args := []any{f.UserID, f.TenantID}
	add := func(clause string, value any) {
		args = append(args, value)
		where += fmt.Sprintf(clause, len(args))
	}
	if f.ConnectionID != nil {
		add(` AND m.connection_id=$%d`, *f.ConnectionID)
	}
	if f.AccessKeyID != nil {
		add(` AND e.access_key_id=$%d`, *f.AccessKeyID)
	}
	if f.EvalRunID != nil {
		add(` AND e.eval_run_id=$%d`, *f.EvalRunID)
	}
	if f.Direction != nil {
		add(` AND m.direction=$%d`, *f.Direction)
	}
	if f.Method != nil {
		add(` AND m.method=$%d`, *f.Method)
	}
	if f.ToolName != nil {
		add(` AND m.tool_name=$%d`, *f.ToolName)
	}
	if f.PolicyDecision != nil {
		add(` AND m.policy_decision=$%d`, *f.PolicyDecision)
	}
	if f.Since != nil {
		add(` AND m.observed_at>=$%d`, *f.Since)
	}
	if f.Until != nil {
		add(` AND m.observed_at<$%d`, *f.Until)
	}
	join := ` FROM vault.mcp_audit_messages m JOIN vault.mcp_audit_exchanges e ON e.id=m.exchange_id`
	var total int
	if err := p.pool.QueryRow(ctx, `SELECT count(*)`+join+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + mcpAuditMessageCols + join + where +
		fmt.Sprintf(` ORDER BY m.observed_at DESC, m.sequence_no DESC OFFSET $%d LIMIT $%d`, len(args)+1, len(args)+2)
	args = append(args, f.Offset, f.Limit)
	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []MCPAuditMessage
	for rows.Next() {
		m, err := scanMCPAuditMessage(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *m)
	}
	return out, total, rows.Err()
}

// DeleteMCPAuditOlderThan deletes a bounded batch of old exchanges and cascades their messages.
func (p *Postgres) DeleteMCPAuditOlderThan(ctx context.Context, cutoff time.Time, batchSize int) (int64, error) {
	if batchSize < 1 {
		return 0, nil
	}
	tag, err := p.pool.Exec(ctx, `
		WITH candidates AS (
			SELECT id FROM vault.mcp_audit_exchanges
			WHERE completed_at IS NOT NULL AND completed_at < $1
			ORDER BY completed_at, id LIMIT $2 FOR UPDATE SKIP LOCKED)
		DELETE FROM vault.mcp_audit_exchanges AS exchange
		USING candidates WHERE exchange.id = candidates.id`, cutoff, batchSize)
	return tag.RowsAffected(), err
}
