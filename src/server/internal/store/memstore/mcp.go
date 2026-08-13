package memstore

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/store"
)

func setIdentity(id *uuid.UUID, createdAt *time.Time) {
	if *id == uuid.Nil {
		*id = uuid.New()
	}
	if createdAt.IsZero() {
		*createdAt = time.Now().UTC()
	}
}

// InsertMCPConnection stores a new MCP connection.
func (m *Mem) InsertMCPConnection(_ context.Context, c *store.MCPConnection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	setIdentity(&c.ID, &c.CreatedAt)
	if c.ProtocolEra == "" {
		c.ProtocolEra = "unknown"
	}
	if c.ProbeStatus == "" {
		c.ProbeStatus = "not_checked"
	}
	if c.UpstreamProtocolMode == "" {
		c.UpstreamProtocolMode = "modern_2026_07"
	}
	if c.LegacyProtocolVersion == "" {
		c.LegacyProtocolVersion = "2025-06-18"
	}
	m.mcpConnections[c.ID] = *c
	return nil
}

// UpdateMCPConnection updates an owner-scoped MCP connection.
func (m *Mem) UpdateMCPConnection(_ context.Context, c *store.MCPConnection) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	existing, ok := m.mcpConnections[c.ID]
	if !ok || existing.UserID != c.UserID {
		return false, nil
	}
	now := time.Now().UTC()
	c.UpdatedAt = &now
	c.ProtocolEra = existing.ProtocolEra
	c.ProbeStatus = existing.ProbeStatus
	c.ProbeCheckedAt = existing.ProbeCheckedAt
	c.ProbeError = existing.ProbeError
	c.ProbeDetail = existing.ProbeDetail
	c.SupportedVersions = append([]string(nil), existing.SupportedVersions...)
	c.ServerName = existing.ServerName
	c.ServerVersion = existing.ServerVersion
	m.mcpConnections[c.ID] = *c
	return true, nil
}

// ListMCPConnections returns a user's MCP connections ordered by name.
func (m *Mem) ListMCPConnections(_ context.Context, userID uuid.UUID) ([]store.MCPConnection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	var out []store.MCPConnection
	for _, c := range m.mcpConnections {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// GetMCPConnectionByID returns an owner-scoped MCP connection by ID.
func (m *Mem) GetMCPConnectionByID(_ context.Context, userID, id uuid.UUID) (*store.MCPConnection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	if c, ok := m.mcpConnections[id]; ok && c.UserID == userID {
		return &c, nil
	}
	return nil, nil
}

// GetMCPConnectionBySlug returns an owner-scoped MCP connection by slug.
func (m *Mem) GetMCPConnectionBySlug(_ context.Context, userID uuid.UUID, slug string) (*store.MCPConnection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	for _, c := range m.mcpConnections {
		if c.UserID == userID && c.Slug == slug {
			return &c, nil
		}
	}
	return nil, nil
}

// DeleteMCPConnection deletes an owner-scoped connection and dependent configuration.
func (m *Mem) DeleteMCPConnection(_ context.Context, userID, id uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	c, ok := m.mcpConnections[id]
	if !ok || c.UserID != userID {
		return false, nil
	}
	delete(m.mcpConnections, id)
	for grantID, grant := range m.mcpGrants {
		if grant.ConnectionID == id {
			delete(m.mcpGrants, grantID)
		}
	}
	for headerID, header := range m.mcpHeaders {
		if header.ConnectionID == id {
			delete(m.mcpHeaders, headerID)
		}
	}
	for policyID, policy := range m.mcpPolicies {
		if policy.ConnectionID == id {
			delete(m.mcpPolicies, policyID)
		}
	}
	for headerID, header := range m.mcpToolHeaders {
		if header.ConnectionID == id {
			delete(m.mcpToolHeaders, headerID)
		}
	}
	for oauthID, oauth := range m.mcpOAuth {
		if oauth.ConnectionID == id {
			delete(m.mcpOAuth, oauthID)
		}
	}
	for stateValue, state := range m.mcpOAuthStates {
		if state.ConnectionID == id {
			delete(m.mcpOAuthStates, stateValue)
		}
	}
	return true, nil
}

// RecordMCPProtocolProbe records probe-owned fields without overwriting editable connection config.
func (m *Mem) RecordMCPProtocolProbe(_ context.Context, result *store.MCPProtocolProbeResult) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	if result == nil {
		return false, store.ErrInvalidMCPProtocolProbe
	}
	if err := store.ValidateMCPProtocolProbe(*result); err != nil {
		return false, err
	}
	connection, ok := m.mcpConnections[result.ConnectionID]
	if !ok || connection.UserID != result.UserID || connection.TenantID != result.TenantID {
		return false, nil
	}
	connection.ProtocolEra = result.ProtocolEra
	connection.ProbeStatus = result.Status
	connection.ProbeCheckedAt = &result.CheckedAt
	connection.ProbeError = result.Error
	connection.ProbeDetail = result.Detail
	connection.SupportedVersions = append([]string(nil), result.SupportedVersions...)
	connection.ServerName = result.ServerName
	connection.ServerVersion = result.ServerVersion
	m.mcpConnections[connection.ID] = connection
	return true, nil
}

// InsertMCPConnectionGrant stores a same-owner access-key grant.
func (m *Mem) InsertMCPConnectionGrant(_ context.Context, g *store.MCPConnectionGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	c, cOK := m.mcpConnections[g.ConnectionID]
	k, kOK := m.accessKeys[g.AccessKeyID]
	if !cOK || !kOK || c.UserID != g.UserID || c.TenantID != g.TenantID ||
		k.UserID != g.UserID || k.TenantID != g.TenantID {
		return store.ErrOwnershipMismatch
	}
	setIdentity(&g.ID, &g.CreatedAt)
	m.mcpGrants[g.ID] = *g
	return nil
}

// ListMCPConnectionGrants returns grants for an owner-scoped connection.
func (m *Mem) ListMCPConnectionGrants(_ context.Context, userID, connectionID uuid.UUID) ([]store.MCPConnectionGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	var out []store.MCPConnectionGrant
	for _, g := range m.mcpGrants {
		if g.UserID == userID && g.ConnectionID == connectionID {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// HasMCPConnectionGrant reports whether an access key may use a connection.
func (m *Mem) HasMCPConnectionGrant(_ context.Context, accessKeyID, connectionID uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	for _, g := range m.mcpGrants {
		if g.AccessKeyID == accessKeyID && g.ConnectionID == connectionID {
			return true, nil
		}
	}
	return false, nil
}

// DeleteMCPConnectionGrant removes an owner-scoped grant.
func (m *Mem) DeleteMCPConnectionGrant(_ context.Context, userID, id uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	if g, ok := m.mcpGrants[id]; ok && g.UserID == userID {
		delete(m.mcpGrants, id)
		return true, nil
	}
	return false, nil
}

// InsertMCPHeaderBinding stores a same-owner credential binding.
func (m *Mem) InsertMCPHeaderBinding(_ context.Context, b *store.MCPHeaderBinding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	c, cOK := m.mcpConnections[b.ConnectionID]
	k, kOK := m.apiKeys[b.CredentialID]
	if !cOK || !kOK || c.UserID != b.UserID || c.TenantID != b.TenantID ||
		k.UserID != b.UserID || k.TenantID != b.TenantID {
		return store.ErrOwnershipMismatch
	}
	setIdentity(&b.ID, &b.CreatedAt)
	m.mcpHeaders[b.ID] = *b
	return nil
}

// ListMCPHeaderBindings returns bindings for an owner-scoped connection.
func (m *Mem) ListMCPHeaderBindings(_ context.Context, userID, connectionID uuid.UUID) ([]store.MCPHeaderBinding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	var out []store.MCPHeaderBinding
	for _, b := range m.mcpHeaders {
		if b.UserID == userID && b.ConnectionID == connectionID {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// DeleteMCPHeaderBinding removes an owner-scoped binding.
func (m *Mem) DeleteMCPHeaderBinding(_ context.Context, userID, id uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	if b, ok := m.mcpHeaders[id]; ok && b.UserID == userID {
		delete(m.mcpHeaders, id)
		return true, nil
	}
	return false, nil
}

// UpsertMCPToolPolicy stores one method and tool decision.
func (m *Mem) UpsertMCPToolPolicy(_ context.Context, policy *store.MCPToolPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if c, ok := m.mcpConnections[policy.ConnectionID]; !ok || c.UserID != policy.UserID || c.TenantID != policy.TenantID {
		return store.ErrOwnershipMismatch
	}
	for id, existing := range m.mcpPolicies {
		if existing.ConnectionID == policy.ConnectionID && existing.Method == policy.Method && existing.ToolName == policy.ToolName {
			now := time.Now().UTC()
			policy.ID, policy.CreatedAt, policy.UpdatedAt = id, existing.CreatedAt, &now
			m.mcpPolicies[id] = *policy
			return nil
		}
	}
	setIdentity(&policy.ID, &policy.CreatedAt)
	m.mcpPolicies[policy.ID] = *policy
	return nil
}

// ListMCPToolPolicies returns policies for an owner-scoped connection.
func (m *Mem) ListMCPToolPolicies(_ context.Context, userID, connectionID uuid.UUID) ([]store.MCPToolPolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	var out []store.MCPToolPolicy
	for _, policy := range m.mcpPolicies {
		if policy.UserID == userID && policy.ConnectionID == connectionID {
			out = append(out, policy)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Method == out[j].Method {
			return out[i].ToolName < out[j].ToolName
		}
		return out[i].Method < out[j].Method
	})
	return out, nil
}

// DeleteMCPToolPolicy removes an owner-scoped tool policy.
func (m *Mem) DeleteMCPToolPolicy(_ context.Context, userID, id uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	if policy, ok := m.mcpPolicies[id]; ok && policy.UserID == userID {
		delete(m.mcpPolicies, id)
		return true, nil
	}
	return false, nil
}

// ReplaceMCPToolParameterHeaders atomically replaces a connection's discovered parameter-header metadata.
func (m *Mem) ReplaceMCPToolParameterHeaders(_ context.Context, userID, tenantID, connectionID uuid.UUID, headers []store.MCPToolParameterHeader) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if err := store.ValidateMCPToolParameterHeaders(headers); err != nil {
		return err
	}
	connection, ok := m.mcpConnections[connectionID]
	if !ok || connection.UserID != userID || connection.TenantID != tenantID {
		return store.ErrOwnershipMismatch
	}
	for i := range headers {
		if headers[i].UserID != uuid.Nil && headers[i].UserID != userID ||
			headers[i].TenantID != uuid.Nil && headers[i].TenantID != tenantID ||
			headers[i].ConnectionID != uuid.Nil && headers[i].ConnectionID != connectionID {
			return store.ErrOwnershipMismatch
		}
	}
	for id, header := range m.mcpToolHeaders {
		if header.ConnectionID == connectionID {
			delete(m.mcpToolHeaders, id)
		}
	}
	for i := range headers {
		header := &headers[i]
		setIdentity(&header.ID, &header.CreatedAt)
		header.UserID, header.TenantID, header.ConnectionID = userID, tenantID, connectionID
		header.ArgumentPath = append([]string(nil), header.ArgumentPath...)
		m.mcpToolHeaders[header.ID] = *header
	}
	return nil
}

// UpsertMCPToolParameterHeaders atomically replaces metadata for explicitly observed tools.
func (m *Mem) UpsertMCPToolParameterHeaders(_ context.Context, userID, tenantID, connectionID uuid.UUID, snapshots []store.MCPToolHeaderSnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if err := store.ValidateMCPToolHeaderSnapshots(snapshots); err != nil {
		return err
	}
	connection, ok := m.mcpConnections[connectionID]
	if !ok || connection.UserID != userID || connection.TenantID != tenantID {
		return store.ErrOwnershipMismatch
	}
	for i := range snapshots {
		snapshot := &snapshots[i]
		for j := range snapshot.Headers {
			header := &snapshot.Headers[j]
			if header.UserID != uuid.Nil && header.UserID != userID ||
				header.TenantID != uuid.Nil && header.TenantID != tenantID ||
				header.ConnectionID != uuid.Nil && header.ConnectionID != connectionID {
				return store.ErrOwnershipMismatch
			}
		}
	}
	observed := make(map[string]struct{}, len(snapshots))
	for _, snapshot := range snapshots {
		observed[snapshot.ToolName] = struct{}{}
	}
	for id, header := range m.mcpToolHeaders {
		if header.ConnectionID == connectionID {
			if _, exists := observed[header.ToolName]; exists {
				delete(m.mcpToolHeaders, id)
			}
		}
	}
	for i := range snapshots {
		snapshot := &snapshots[i]
		for j := range snapshot.Headers {
			header := &snapshot.Headers[j]
			header.ToolName = snapshot.ToolName
			setIdentity(&header.ID, &header.CreatedAt)
			header.UserID, header.TenantID, header.ConnectionID = userID, tenantID, connectionID
			header.ArgumentPath = append([]string(nil), header.ArgumentPath...)
			m.mcpToolHeaders[header.ID] = *header
		}
	}
	return nil
}

// ListMCPToolParameterHeaders returns discovered parameter headers for one owner-scoped tool.
func (m *Mem) ListMCPToolParameterHeaders(_ context.Context, userID, connectionID uuid.UUID, toolName string) ([]store.MCPToolParameterHeader, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	var out []store.MCPToolParameterHeader
	for _, header := range m.mcpToolHeaders {
		if header.UserID == userID && header.ConnectionID == connectionID && header.ToolName == toolName {
			header.ArgumentPath = append([]string(nil), header.ArgumentPath...)
			out = append(out, header)
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].HeaderName) < strings.ToLower(out[j].HeaderName) })
	return out, nil
}

// InsertMCPOAuthAuthorization stores a same-owner connection authorization.
func (m *Mem) InsertMCPOAuthAuthorization(_ context.Context, a *store.MCPOAuthAuthorization) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if c, ok := m.mcpConnections[a.ConnectionID]; !ok || c.UserID != a.UserID || c.TenantID != a.TenantID {
		return store.ErrOwnershipMismatch
	}
	setIdentity(&a.ID, &a.CreatedAt)
	m.mcpOAuth[a.ID] = *a
	return nil
}

// UpdateMCPOAuthAuthorization updates an owner-scoped connection authorization.
func (m *Mem) UpdateMCPOAuthAuthorization(_ context.Context, a *store.MCPOAuthAuthorization) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	existing, ok := m.mcpOAuth[a.ID]
	if !ok || existing.UserID != a.UserID || existing.ConnectionID != a.ConnectionID {
		return false, nil
	}
	now := time.Now().UTC()
	a.UpdatedAt = &now
	m.mcpOAuth[a.ID] = *a
	return true, nil
}

// GetMCPOAuthAuthorization returns an owner-scoped connection authorization.
func (m *Mem) GetMCPOAuthAuthorization(_ context.Context, userID, connectionID uuid.UUID) (*store.MCPOAuthAuthorization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	for _, a := range m.mcpOAuth {
		if a.UserID == userID && a.ConnectionID == connectionID {
			return &a, nil
		}
	}
	return nil, nil
}

// DeleteMCPOAuthAuthorization removes an owner-scoped connection authorization.
func (m *Mem) DeleteMCPOAuthAuthorization(_ context.Context, userID, connectionID uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	for id, a := range m.mcpOAuth {
		if a.UserID == userID && a.ConnectionID == connectionID {
			delete(m.mcpOAuth, id)
			return true, nil
		}
	}
	return false, nil
}

// InsertMCPOAuthState stores a same-owner in-flight OAuth state.
func (m *Mem) InsertMCPOAuthState(_ context.Context, state *store.MCPOAuthState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if c, ok := m.mcpConnections[state.ConnectionID]; !ok || c.UserID != state.UserID || c.TenantID != state.TenantID {
		return store.ErrOwnershipMismatch
	}
	if state.CreatedAt.IsZero() {
		state.CreatedAt = time.Now().UTC()
	}
	m.mcpOAuthStates[state.State] = *state
	return nil
}

// ClaimMCPOAuthState atomically consumes an OAuth state.
func (m *Mem) ClaimMCPOAuthState(_ context.Context, state string) (*store.MCPOAuthState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	s, ok := m.mcpOAuthStates[state]
	if !ok {
		return nil, nil
	}
	delete(m.mcpOAuthStates, state)
	return &s, nil
}

// InsertMCPAuditExchange stores an HTTP-level MCP exchange.
func (m *Mem) InsertMCPAuditExchange(_ context.Context, exchange *store.MCPAuditExchange) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	setIdentity(&exchange.ID, &exchange.StartedAt)
	m.mcpExchanges[exchange.ID] = *exchange
	return nil
}

// CompleteMCPAuditExchange updates an owner-scoped MCP exchange.
func (m *Mem) CompleteMCPAuditExchange(_ context.Context, exchange *store.MCPAuditExchange) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	existing, ok := m.mcpExchanges[exchange.ID]
	if !ok || existing.UserID != exchange.UserID || existing.TenantID != exchange.TenantID {
		return false, nil
	}
	m.mcpExchanges[exchange.ID] = *exchange
	return true, nil
}

// InsertMCPAuditMessage stores one inspected JSON-RPC message.
func (m *Mem) InsertMCPAuditMessage(_ context.Context, message *store.MCPAuditMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	exchange, ok := m.mcpExchanges[message.ExchangeID]
	if !ok || exchange.ConnectionID != message.ConnectionID || exchange.UserID != message.UserID ||
		exchange.TenantID != message.TenantID {
		return store.ErrOwnershipMismatch
	}
	setIdentity(&message.ID, &message.ObservedAt)
	m.mcpMessages[message.ID] = *message
	return nil
}

// QueryMCPAudit returns an owner-scoped, filtered page of MCP messages.
func (m *Mem) QueryMCPAudit(_ context.Context, f store.MCPAuditFilter) ([]store.MCPAuditMessage, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, 0, err
	}
	var matched []store.MCPAuditMessage
	for _, message := range m.mcpMessages {
		exchange, ok := m.mcpExchanges[message.ExchangeID]
		if !ok || message.UserID != f.UserID || message.TenantID != f.TenantID {
			continue
		}
		if f.ConnectionID != nil && message.ConnectionID != *f.ConnectionID ||
			f.AccessKeyID != nil && exchange.AccessKeyID != *f.AccessKeyID ||
			f.EvalRunID != nil && (exchange.EvalRunID == nil || *exchange.EvalRunID != *f.EvalRunID) ||
			f.Direction != nil && message.Direction != *f.Direction ||
			f.Method != nil && (message.Method == nil || *message.Method != *f.Method) ||
			f.ToolName != nil && (message.ToolName == nil || *message.ToolName != *f.ToolName) ||
			f.PolicyDecision != nil && message.PolicyDecision != *f.PolicyDecision ||
			f.Since != nil && message.ObservedAt.Before(*f.Since) ||
			f.Until != nil && !message.ObservedAt.Before(*f.Until) {
			continue
		}
		matched = append(matched, message)
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].ObservedAt.Equal(matched[j].ObservedAt) {
			return matched[i].SequenceNo > matched[j].SequenceNo
		}
		return matched[i].ObservedAt.After(matched[j].ObservedAt)
	})
	total := len(matched)
	lo := f.Offset
	if lo > total {
		lo = total
	}
	hi := lo + f.Limit
	if hi > total {
		hi = total
	}
	return matched[lo:hi], total, nil
}
