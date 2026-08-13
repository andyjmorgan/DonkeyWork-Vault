package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/mcp"
	"donkeywork.dev/vault-server/internal/mcplegacy"
	"donkeywork.dev/vault-server/internal/service"
	"donkeywork.dev/vault-server/internal/store"
)

const maxMCPAuditPayload = 256 << 10

const mcpProbeRequestID = "dwv-probe"

var errMCPGrantRequired = errors.New("MCP connection grant required")

func (s *Server) handleListMCPConnections(w http.ResponseWriter, r *http.Request) {
	rows, err := s.deps.MCP.ListConnections(r.Context())
	if writeServiceError(w, err) {
		return
	}
	out := make([]mcpConnectionDTO, len(rows))
	for i := range rows {
		out[i] = toMCPConnectionDTO(rows[i])
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleUpsertMCPConnection(w http.ResponseWriter, r *http.Request) {
	var dto upsertMCPConnectionRequest
	if err := decodeJSON(r, &dto); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body.")
		return
	}
	enabled := true
	if dto.Enabled != nil {
		enabled = *dto.Enabled
	}
	if pathID := chi.URLParam(r, "id"); pathID != "" {
		id, ok := uuidParam(pathID)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid id.")
			return
		}
		dto.ID = id
	}
	row, err := s.deps.MCP.UpsertConnection(r.Context(), service.MCPConnectionParams{
		ID: dto.ID, Slug: dto.Slug, Name: dto.Name, Description: dto.Description,
		UpstreamURL: dto.UpstreamURL, AuthMode: dto.AuthMode, AuditMode: dto.AuditMode,
		UpstreamProtocolMode: dto.UpstreamProtocolMode, LegacyProtocolVersion: dto.LegacyProtocolVersion, Enabled: enabled,
	})
	if writeServiceError(w, err) {
		return
	}
	if row == nil {
		writeError(w, http.StatusNotFound, "MCP connection not found.")
		return
	}
	writeJSON(w, http.StatusOK, toMCPConnectionDTO(*row))
}

func (s *Server) handleDeleteMCPConnection(w http.ResponseWriter, r *http.Request) {
	id, ok := uuidParam(chi.URLParam(r, "id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id.")
		return
	}
	deleted, err := s.deps.MCP.DeleteConnection(r.Context(), id)
	if writeServiceError(w, err) {
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "MCP connection not found.")
		return
	}
	_ = s.legacy.remove(r.Context(), id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMCPProtocolProbe(w http.ResponseWriter, r *http.Request) {
	id, ok := mcpConnectionID(w, r)
	if !ok {
		return
	}
	resolved, err := s.deps.MCP.ResolveProbe(r.Context(), id)
	if writeServiceError(w, err) {
		return
	}
	if resolved == nil {
		writeError(w, http.StatusNotFound, "MCP connection not found.")
		return
	}
	body := mcpProbeRequestBody()
	upstream, err := http.NewRequestWithContext(r.Context(), http.MethodPost, resolved.Connection.UpstreamURL, bytes.NewReader(body)) //nolint:gosec // G704: validated stored URL and safe client transport.
	if err != nil {                                                                                                                   //coverage:ignore the stored URL and constant method/body were already validated.
		writeError(w, http.StatusInternalServerError, "MCP protocol probe unavailable.")
		return
	}
	upstream.Header.Set("Content-Type", "application/json")
	upstream.Header.Set("Accept", "application/json, text/event-stream")
	upstream.Header.Set("MCP-Protocol-Version", mcp.ProtocolVersion)
	upstream.Header.Set("Mcp-Method", "server/discover")
	for name, values := range resolved.Headers {
		for _, value := range values {
			upstream.Header.Add(name, value)
		}
	}
	if resolved.Connection.AuthMode == "oauth" {
		token, tokenErr := s.deps.MCPOAuth.AccessToken(r.Context(), resolved.Connection.ID)
		if tokenErr != nil {
			connection, recordErr := s.recordMCPProbe(r.Context(), resolved.Connection, mcp.ProbeResult{Class: mcp.ProbeAuthRequired, Reason: mcp.ProbeReasonAuthorizationUnavailable})
			if recordErr != nil {
				writeError(w, http.StatusServiceUnavailable, "MCP probe storage unavailable.")
				return
			}
			writeJSON(w, http.StatusOK, toMCPConnectionDTO(connection))
			return
		}
		upstream.Header.Set("Authorization", token.TokenType+" "+token.AccessToken)
	}
	probeClient := *s.deps.MCPClient
	// Probe credentials must never be replayed to a redirect target. The returned 3xx is itself
	// useful classifier evidence, and an operator can configure the canonical endpoint explicitly.
	probeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, requestErr := probeClient.Do(upstream) //nolint:gosec // G704: validated stored URL and SSRF-safe client.
	if requestErr != nil {
		result := mcp.ProbeResult{Class: mcp.ProbeUnavailable, Reason: mcp.ProbeReasonNetworkFailure}
		connection, recordErr := s.recordMCPProbe(r.Context(), resolved.Connection, result)
		if recordErr != nil {
			writeError(w, http.StatusServiceUnavailable, "MCP probe storage unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, toMCPConnectionDTO(connection))
		return
	}
	defer func() { _ = response.Body.Close() }()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxRequestBody+1))
	var result mcp.ProbeResult
	switch {
	case readErr != nil || len(responseBody) > maxRequestBody:
		result = mcp.ProbeResult{Class: mcp.ProbeUnavailable, Reason: mcp.ProbeReasonResponseTooLarge}
	case strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream"):
		result = classifyMCPProbeSSE(response.StatusCode, response.Header.Get("Content-Type"), responseBody)
	default:
		result = mcp.ClassifyProbe(mcp.ProbeInput{StatusCode: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: responseBody, RequestID: mcp.ID{Kind: mcp.IDString, Value: mcpProbeRequestID}})
	}
	connection, err := s.recordMCPProbe(r.Context(), resolved.Connection, result)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "MCP probe storage unavailable.")
		return
	}
	writeJSON(w, http.StatusOK, toMCPConnectionDTO(connection))
}

func mcpProbeRequestBody() []byte {
	return []byte(`{"jsonrpc":"2.0","id":"` + mcpProbeRequestID + `","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"` + mcp.ProtocolVersion + `","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"DonkeyWork Vault","version":"probe"}}}}`)
}

func classifyMCPProbeSSE(status int, contentType string, body []byte) mcp.ProbeResult {
	pending := bytes.NewBuffer(body)
	for pending.Len() > 0 {
		event, ok := takeSSEEvent(pending)
		if !ok {
			break
		}
		data := sseData(event)
		if len(data) == 0 {
			continue
		}
		message, err := mcp.InspectServer(data, nil)
		if err == nil && message.Kind == mcp.KindNotification {
			continue
		}
		result := mcp.ClassifyProbe(mcp.ProbeInput{StatusCode: status, ContentType: "application/json", Body: data, RequestID: mcp.ID{Kind: mcp.IDString, Value: mcpProbeRequestID}})
		if result.Class != mcp.ProbeIncompatible || result.Reason != mcp.ProbeReasonMalformedSuccess {
			return result
		}
	}
	return mcp.ClassifyProbe(mcp.ProbeInput{StatusCode: status, ContentType: contentType, Body: body, RequestID: mcp.ID{Kind: mcp.IDString, Value: mcpProbeRequestID}})
}

func (s *Server) recordMCPProbe(ctx context.Context, connection store.MCPConnection, result mcp.ProbeResult) (store.MCPConnection, error) {
	caller := contracts.CallerFrom(ctx)
	era, status := string(result.Class), "error"
	switch result.Class {
	case mcp.ProbeModern202607:
		status = "compatible"
	case mcp.ProbeLegacySessionLikely, mcp.ProbeIncompatible:
		status = "incompatible"
	case mcp.ProbeAuthRequired:
		era, status = "unknown", "auth_required"
	case mcp.ProbeUnavailable:
		era, status = "unknown", "unreachable"
	case mcp.ProbeUnknown:
		era = "unknown"
	}
	detail := string(result.Reason)
	probe := &store.MCPProtocolProbeResult{ConnectionID: connection.ID, UserID: caller.UserID, TenantID: caller.TenantID,
		ProtocolEra: era, Status: status, CheckedAt: time.Now().UTC(), Detail: &detail,
		SupportedVersions: result.SupportedVersions}
	if result.Server.Name != "" {
		probe.ServerName = &result.Server.Name
	}
	if result.Server.Version != "" {
		probe.ServerVersion = &result.Server.Version
	}
	updated, err := s.deps.MCP.Store().RecordMCPProtocolProbe(ctx, probe)
	if err != nil {
		return connection, err
	}
	if !updated { //coverage:ignore the owner-scoped connection was resolved immediately before recording.
		return connection, errors.New("MCP connection no longer exists")
	}
	connection.ProtocolEra = probe.ProtocolEra
	connection.ProbeStatus = probe.Status
	connection.ProbeCheckedAt = &probe.CheckedAt
	connection.ProbeError = probe.Error
	connection.ProbeDetail = probe.Detail
	connection.SupportedVersions = probe.SupportedVersions
	connection.ServerName = probe.ServerName
	connection.ServerVersion = probe.ServerVersion
	return connection, nil
}

func (s *Server) handleListMCPGrants(w http.ResponseWriter, r *http.Request) {
	id, ok := mcpConnectionID(w, r)
	if !ok {
		return
	}
	rows, err := s.deps.MCP.ListGrants(r.Context(), id)
	if writeServiceError(w, err) {
		return
	}
	out := make([]mcpGrantDTO, len(rows))
	for i, row := range rows {
		out[i] = mcpGrantDTO{ID: row.ID, ConnectionID: row.ConnectionID, AccessKeyID: row.AccessKeyID, CreatedAt: row.CreatedAt}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateMCPGrant(w http.ResponseWriter, r *http.Request) {
	id, ok := mcpConnectionID(w, r)
	if !ok {
		return
	}
	var dto createMCPGrantRequest
	if err := decodeJSON(r, &dto); err != nil || dto.AccessKeyID == uuid.Nil {
		writeError(w, http.StatusBadRequest, "invalid request body.")
		return
	}
	row, err := s.deps.MCP.Grant(r.Context(), id, dto.AccessKeyID)
	if writeServiceError(w, err) {
		return
	}
	if row == nil {
		writeError(w, http.StatusNotFound, "connection or access key not found.")
		return
	}
	writeJSON(w, http.StatusOK, mcpGrantDTO{ID: row.ID, ConnectionID: row.ConnectionID, AccessKeyID: row.AccessKeyID, CreatedAt: row.CreatedAt})
}

func (s *Server) handleDeleteMCPGrant(w http.ResponseWriter, r *http.Request) {
	s.handleMCPChildDelete(w, r, s.deps.MCP.DeleteGrant)
}

func (s *Server) handleListMCPHeaders(w http.ResponseWriter, r *http.Request) {
	id, ok := mcpConnectionID(w, r)
	if !ok {
		return
	}
	rows, err := s.deps.MCP.ListHeaderBindings(r.Context(), id)
	if writeServiceError(w, err) {
		return
	}
	out := make([]mcpHeaderBindingDTO, len(rows))
	for i, row := range rows {
		out[i] = mcpHeaderBindingDTO{ID: row.ID, ConnectionID: row.ConnectionID, CredentialID: row.CredentialID, HeaderName: row.HeaderName, CreatedAt: row.CreatedAt}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateMCPHeader(w http.ResponseWriter, r *http.Request) {
	id, ok := mcpConnectionID(w, r)
	if !ok {
		return
	}
	var dto createMCPHeaderBindingRequest
	if err := decodeJSON(r, &dto); err != nil || dto.CredentialID == uuid.Nil {
		writeError(w, http.StatusBadRequest, "invalid request body.")
		return
	}
	row, err := s.deps.MCP.BindHeader(r.Context(), id, dto.CredentialID, dto.HeaderName)
	if writeServiceError(w, err) {
		return
	}
	if row == nil {
		writeError(w, http.StatusNotFound, "connection or credential not found.")
		return
	}
	writeJSON(w, http.StatusOK, mcpHeaderBindingDTO{ID: row.ID, ConnectionID: row.ConnectionID, CredentialID: row.CredentialID, HeaderName: row.HeaderName, CreatedAt: row.CreatedAt})
}

func (s *Server) handleDeleteMCPHeader(w http.ResponseWriter, r *http.Request) {
	s.handleMCPChildDelete(w, r, s.deps.MCP.DeleteHeaderBinding)
}

func (s *Server) handleListMCPPolicies(w http.ResponseWriter, r *http.Request) {
	id, ok := mcpConnectionID(w, r)
	if !ok {
		return
	}
	rows, err := s.deps.MCP.ListPolicies(r.Context(), id)
	if writeServiceError(w, err) {
		return
	}
	out := make([]mcpToolPolicyDTO, len(rows))
	for i, row := range rows {
		out[i] = mcpToolPolicyDTO{ID: row.ID, ConnectionID: row.ConnectionID, Method: row.Method, ToolName: row.ToolName, Allow: row.Allow, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleUpsertMCPPolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := mcpConnectionID(w, r)
	if !ok {
		return
	}
	var dto upsertMCPToolPolicyRequest
	if err := decodeJSON(r, &dto); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body.")
		return
	}
	row, err := s.deps.MCP.PutPolicy(r.Context(), id, dto.Method, dto.ToolName, dto.Allow)
	if writeServiceError(w, err) {
		return
	}
	if row == nil {
		writeError(w, http.StatusNotFound, "MCP connection not found.")
		return
	}
	writeJSON(w, http.StatusOK, mcpToolPolicyDTO{ID: row.ID, ConnectionID: row.ConnectionID, Method: row.Method, ToolName: row.ToolName, Allow: row.Allow, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt})
}

func (s *Server) handleDeleteMCPPolicy(w http.ResponseWriter, r *http.Request) {
	s.handleMCPChildDelete(w, r, s.deps.MCP.DeletePolicy)
}

func (s *Server) handleConfigureMCPOAuth(w http.ResponseWriter, r *http.Request) {
	id, ok := mcpConnectionID(w, r)
	if !ok {
		return
	}
	var dto configureMCPOAuthRequest
	if err := decodeJSON(r, &dto); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body.")
		return
	}
	if err := s.deps.MCPOAuth.ConfigureClient(r.Context(), id, dto.Issuer, dto.ClientID, dto.ClientSecret, dto.Scopes); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleConnectMCPOAuth(w http.ResponseWriter, r *http.Request) {
	id, ok := mcpConnectionID(w, r)
	if !ok {
		return
	}
	redirectURI := strings.TrimSuffix(s.deps.PublicBaseURL, "/") + "/api/mcp/oauth/callback"
	result, err := s.deps.MCPOAuth.Begin(r.Context(), id, redirectURI)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, mcpOAuthConnectResponse{AuthorizeURL: result.AuthorizationURL, ExpiresAt: result.ExpiresAt})
}

func (s *Server) handleDeleteMCPOAuth(w http.ResponseWriter, r *http.Request) {
	id, ok := mcpConnectionID(w, r)
	if !ok {
		return
	}
	deleted, err := s.deps.MCP.Store().DeleteMCPOAuthAuthorization(r.Context(), contracts.CallerFrom(r.Context()).UserID, id)
	if writeServiceError(w, err) {
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "MCP OAuth configuration not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMCPOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if oauthError := r.URL.Query().Get("error"); oauthError != "" {
		writeError(w, http.StatusBadRequest, "MCP OAuth authorization was denied.")
		return
	}
	if _, err := s.deps.MCPOAuth.Complete(r.Context(), r.URL.Query().Get("code"), r.URL.Query().Get("state")); err != nil {
		writeError(w, http.StatusBadRequest, "MCP OAuth authorization failed.")
		return
	}
	http.Redirect(w, r, "/mcp?oauth=connected", http.StatusFound)
}

func (s *Server) handleMCPChildDelete(w http.ResponseWriter, r *http.Request, deleteFn func(context.Context, uuid.UUID) (bool, error)) {
	id, ok := uuidParam(chi.URLParam(r, "id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id.")
		return
	}
	deleted, err := deleteFn(r.Context(), id)
	if writeServiceError(w, err) {
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "MCP configuration not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func mcpConnectionID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, ok := uuidParam(chi.URLParam(r, "connectionID"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid connection id.")
	}
	return id, ok
}

func (s *Server) handleMCPAudit(w http.ResponseWriter, r *http.Request) {
	caller := contracts.CallerFrom(r.Context())
	filter := store.MCPAuditFilter{UserID: caller.UserID, TenantID: caller.TenantID,
		Limit: queryInt(r, "limit", 100, 1, 500), Offset: queryInt(r, "offset", 0, 0, 1_000_000)}
	if raw := r.URL.Query().Get("connectionId"); raw != "" {
		id, ok := uuidParam(raw)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid connectionId.")
			return
		}
		filter.ConnectionID = &id
	}
	filter.EvalRunID = queryString(r, "evalRunId")
	filter.Direction = queryString(r, "direction")
	filter.Method = queryString(r, "method")
	filter.ToolName = queryString(r, "toolName")
	filter.PolicyDecision = queryString(r, "policyDecision")
	rows, total, err := s.deps.MCP.Store().QueryMCPAudit(r.Context(), filter)
	if writeServiceError(w, err) {
		return
	}
	out := make([]mcpAuditMessageDTO, len(rows))
	for i := range rows {
		out[i] = toMCPAuditMessageDTO(rows[i])
	}
	writeJSON(w, http.StatusOK, mcpAuditPageResponse{Items: out, Total: total, Limit: filter.Limit, Offset: filter.Offset})
}

func (s *Server) handleMCPProxy(w http.ResponseWriter, r *http.Request) {
	if !s.validMCPOrigin(r.Header.Get("Origin")) {
		writeError(w, http.StatusForbidden, "invalid Origin for MCP endpoint.")
		return
	}
	info := audit.RequestInfoFrom(r.Context())
	if info.AccessKeyID == nil {
		writeError(w, http.StatusForbidden, "MCP proxy requires a vault access key.")
		return
	}
	resolved, err := s.deps.MCP.ResolveProxy(r.Context(), chi.URLParam(r, "slug"), *info.AccessKeyID)
	if err != nil || resolved == nil {
		if err != nil && strings.Contains(err.Error(), "grant required") {
			writeError(w, http.StatusForbidden, errMCPGrantRequired.Error())
			return
		}
		writeError(w, http.StatusNotFound, "MCP connection not found.")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "unable to read MCP request.")
		return
	}
	exchange := newMCPExchange(r, resolved.Connection, *info.AccessKeyID, int64(len(body)))
	if err := s.deps.MCP.Store().InsertMCPAuditExchange(r.Context(), exchange); err != nil {
		writeError(w, http.StatusServiceUnavailable, "MCP audit storage unavailable.")
		return
	}
	message, err := mcp.InspectClient(body, r.Header, mcp.Options{RequestStateHMACKey: s.deps.MCPAuditHMACKey})
	if err == nil && message.Audit.Method == "tools/call" {
		parameterHeaders, loadErr := s.deps.MCP.Store().ListMCPToolParameterHeaders(r.Context(), resolved.Connection.UserID, resolved.Connection.ID, message.Audit.ToolName)
		if loadErr != nil {
			s.completeMCPExchange(r.Context(), exchange, http.StatusServiceUnavailable, "failed", 0, "metadata")
			writeError(w, http.StatusServiceUnavailable, "MCP tool metadata unavailable.")
			return
		}
		bindings := make([]mcp.ParamHeader, len(parameterHeaders))
		for i, header := range parameterHeaders {
			bindings[i] = mcp.ParamHeader{Name: header.HeaderName, ArgumentPath: header.ArgumentPath, Required: header.Required}
		}
		message, err = mcp.InspectClient(body, r.Header, mcp.Options{RequestStateHMACKey: s.deps.MCPAuditHMACKey, ParamHeaders: bindings})
	}
	if err == nil && !validMCPContentHeaders(r.Header) {
		err = errors.New("invalid MCP content negotiation headers")
	}
	if err != nil {
		requestAudit := rawMCPAuditRecord(exchange, 1, "client_to_server", "malformed", body, resolved.Connection.AuditMode)
		requestAudit.PolicyDecision = "malformed"
		if insertErr := s.deps.MCP.Store().InsertMCPAuditMessage(r.Context(), requestAudit); insertErr != nil {
			s.completeMCPExchange(r.Context(), exchange, http.StatusServiceUnavailable, "audit_failed", 0, "audit")
			writeError(w, http.StatusServiceUnavailable, "MCP audit storage unavailable.")
			return
		}
		s.completeMCPExchange(r.Context(), exchange, http.StatusBadRequest, "malformed", 0, "protocol")
		code := -32600
		if mcp.IsErrorKind(err, mcp.ErrorHeaderMismatch) {
			code = mcp.HeaderMismatchCode
		}
		writeMCPError(w, http.StatusBadRequest, code, "invalid MCP request metadata", nil)
		return
	}
	decision := resolved.Policy.Evaluate(message)
	if message.Audit.Method == "server/discover" {
		decision = mcp.Decision{Allowed: true}
	}
	requestAudit := mcpAuditRecord(exchange, 1, "client_to_server", message.Kind, message.ID, message.Audit, 0, body, resolved.Connection.AuditMode)
	if decision.Allowed {
		requestAudit.PolicyDecision = "allowed"
	} else {
		requestAudit.PolicyDecision = "denied"
		requestAudit.PolicyRule = strPtr(decision.Field + ":" + decision.Value)
	}
	if err := s.deps.MCP.Store().InsertMCPAuditMessage(r.Context(), requestAudit); err != nil {
		s.completeMCPExchange(r.Context(), exchange, http.StatusServiceUnavailable, "audit_failed", 0, "audit")
		writeError(w, http.StatusServiceUnavailable, "MCP audit storage unavailable.")
		return
	}
	if !decision.Allowed {
		s.completeMCPExchange(r.Context(), exchange, http.StatusForbidden, "denied", 0, "policy")
		writeMCPError(w, http.StatusForbidden, -32600, "request denied by MCP gateway policy", messageIDValue(message.ID))
		return
	}
	if message.Audit.Method == "server/discover" {
		s.handleMCPDiscover(w, r, exchange, resolved, message)
		return
	}
	// The URL was parsed and restricted to absolute HTTPS by MCPService.UpsertConnection; the
	// injected client also resolves through the link-local-blocking safe transport.
	upstream, err := http.NewRequestWithContext(r.Context(), http.MethodPost, resolved.Connection.UpstreamURL, bytes.NewReader(body)) //nolint:gosec // G704: validated stored URL, not an unchecked request URL
	if err != nil {
		s.completeMCPExchange(r.Context(), exchange, http.StatusBadGateway, "failed", 0, "request")
		writeError(w, http.StatusBadGateway, "invalid MCP upstream.")
		return
	}
	copyMCPRequestHeaders(upstream.Header, r.Header)
	for name, values := range resolved.Headers {
		upstream.Header.Del(name)
		for _, value := range values {
			upstream.Header.Add(name, value)
		}
	}
	if resolved.Connection.AuthMode == "oauth" {
		token, tokenErr := s.deps.MCPOAuth.AccessToken(r.Context(), resolved.Connection.ID)
		if tokenErr != nil {
			s.completeMCPExchange(r.Context(), exchange, http.StatusBadGateway, "failed", 0, "oauth")
			writeError(w, http.StatusBadGateway, "MCP upstream authorization unavailable.")
			return
		}
		upstream.Header.Set("Authorization", token.TokenType+" "+token.AccessToken)
	}
	var response *http.Response
	responseSequence := int64(2)
	if resolved.Connection.UpstreamProtocolMode == "legacy_session" {
		adapter, adapterErr := s.legacy.adapter(resolved.Connection, s.deps.MCPClient, s.deps.ServiceVersion)
		if adapterErr != nil {
			err = adapterErr
		} else {
			response, err = adapter.DoObserved(r.Context(), upstream, s.legacyLifecycleObserver(r.Context(), exchange, resolved.Connection.AuditMode, &responseSequence))
		}
	} else {
		response, err = s.deps.MCPClient.Do(upstream) //nolint:gosec // G704: destination passed the service validation and safe dialer
	}
	if err != nil {
		if mcplegacy.IsErrorKind(err, mcplegacy.ErrorObserver) {
			s.completeMCPExchange(r.Context(), exchange, http.StatusServiceUnavailable, "audit_failed", 0, "audit")
			writeError(w, http.StatusServiceUnavailable, "MCP audit storage unavailable.")
			return
		}
		s.completeMCPExchange(r.Context(), exchange, http.StatusBadGateway, "failed", 0, "upstream")
		writeError(w, http.StatusBadGateway, "MCP upstream unavailable.")
		return
	}
	defer func() { _ = response.Body.Close() }()
	copyMCPResponseHeaders(w.Header(), response.Header)
	if message.Kind == mcp.KindNotification && response.StatusCode == http.StatusAccepted {
		w.WriteHeader(response.StatusCode)
		s.completeMCPExchange(r.Context(), exchange, response.StatusCode, "complete", 0, "")
		return
	}
	contentType := strings.ToLower(response.Header.Get("Content-Type"))
	legacy := resolved.Connection.UpstreamProtocolMode == "legacy_session"
	if strings.HasPrefix(contentType, "text/event-stream") {
		if message.Audit.Method == "tools/list" {
			s.proxyMCPToolsListSSE(w, r, response, exchange, resolved, message, legacy, responseSequence)
			return
		}
		s.proxyMCPSSE(w, r, response, exchange, resolved.Connection, message.Audit.Method, legacy, responseSequence)
		return
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxRequestBody+1))
	if readErr != nil || len(responseBody) > maxRequestBody {
		s.completeMCPExchange(r.Context(), exchange, http.StatusBadGateway, "failed", 0, "response")
		writeError(w, http.StatusBadGateway, "invalid MCP upstream response.")
		return
	}
	originalResponseBytes := int64(len(responseBody))
	if legacy {
		responseBody, readErr = mcp.UpgradeLegacyResponse(responseBody, message.Audit.Method)
		if readErr != nil {
			s.completeMCPExchange(r.Context(), exchange, http.StatusBadGateway, "failed", originalResponseBytes, "protocol")
			writeError(w, http.StatusBadGateway, "invalid MCP upstream response.")
			return
		}
	}
	serverMessage, inspectErr := mcp.InspectServer(responseBody, s.deps.MCPAuditHMACKey)
	if inspectErr == nil && serverMessage.Kind == mcp.KindResult {
		responseBody, inspectErr = s.transformMCPResponse(r.Context(), message, resolved, responseBody)
		if inspectErr == nil {
			serverMessage, inspectErr = mcp.InspectServer(responseBody, s.deps.MCPAuditHMACKey)
		}
	}
	if inspectErr != nil {
		s.completeMCPExchange(r.Context(), exchange, http.StatusBadGateway, "failed", originalResponseBytes, "protocol")
		writeError(w, http.StatusBadGateway, "invalid MCP upstream response.")
		return
	}
	if message.Audit.Method == "tools/list" {
		w.Header().Set("Cache-Control", "private")
	}
	responseAudit := mcpAuditRecord(exchange, responseSequence, "server_to_client", serverMessage.Kind, serverMessage.ID, serverMessage.Audit, serverMessage.ErrorCode, responseBody, resolved.Connection.AuditMode)
	responseAudit.PolicyDecision = "allowed"
	if err := s.deps.MCP.Store().InsertMCPAuditMessage(r.Context(), responseAudit); err != nil {
		s.completeMCPExchange(r.Context(), exchange, http.StatusServiceUnavailable, "audit_failed", originalResponseBytes, "audit")
		writeError(w, http.StatusServiceUnavailable, "MCP audit storage unavailable.")
		return
	}
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(responseBody) //nolint:gosec // G705: validated JSON is returned with application/json, never rendered as HTML.
	s.completeMCPExchange(r.Context(), exchange, response.StatusCode, "complete", originalResponseBytes, "")
}

func (s *Server) handleMCPDiscover(w http.ResponseWriter, r *http.Request, exchange *store.MCPAuditExchange, resolved *service.MCPResolvedConnection, message mcp.ClientMessage) {
	capabilities := make([]mcp.Capability, 0, 1)
	if resolved.Policy.AllowsMethod("tools/list") && resolved.Policy.AllowsMethod("tools/call") {
		capabilities = append(capabilities, mcp.Capability{Name: "tools", Settings: json.RawMessage(`{}`)})
	}
	responseBody, err := mcp.BuildDiscover(message.ID, mcp.GatewayIdentity{
		Name: "DonkeyWork Vault", Version: s.deps.ServiceVersion,
		Description: "Stateless MCP credential and audit gateway", WebsiteURL: s.deps.PublicBaseURL,
	}, capabilities, int64(time.Hour/time.Millisecond))
	if err != nil {
		return //coverage:ignore validated request ID, constant identity, capabilities, and TTL make construction infallible.
	}
	serverMessage, err := mcp.InspectServer(responseBody, s.deps.MCPAuditHMACKey)
	if err != nil { //coverage:ignore BuildDiscover returns a validated server response.
		return //coverage:ignore BuildDiscover returns a validated server response.
	}
	responseAudit := mcpAuditRecord(exchange, 2, "server_to_client", serverMessage.Kind, serverMessage.ID, serverMessage.Audit, serverMessage.ErrorCode, responseBody, resolved.Connection.AuditMode)
	responseAudit.PolicyDecision = "allowed"
	if err := s.deps.MCP.Store().InsertMCPAuditMessage(r.Context(), responseAudit); err != nil {
		s.completeMCPExchange(r.Context(), exchange, http.StatusServiceUnavailable, "audit_failed", int64(len(responseBody)), "audit")
		writeError(w, http.StatusServiceUnavailable, "MCP audit storage unavailable.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(responseBody) //nolint:gosec // G705: BuildDiscover produced validated JSON served as application/json.
	s.completeMCPExchange(r.Context(), exchange, http.StatusOK, "complete", int64(len(responseBody)), "")
}

func (s *Server) transformMCPResponse(ctx context.Context, request mcp.ClientMessage, resolved *service.MCPResolvedConnection, body []byte) ([]byte, error) {
	if request.Audit.Method != "tools/list" {
		return body, nil
	}
	transformed, err := mcp.TransformToolsList(body, resolved.Policy.AllowsTool)
	if err != nil {
		return nil, err
	}
	caller := contracts.CallerFrom(ctx)
	snapshots := make([]store.MCPToolHeaderSnapshot, len(transformed.Tools))
	flat := make([]store.MCPToolParameterHeader, 0)
	for i, tool := range transformed.Tools {
		snapshot := store.MCPToolHeaderSnapshot{ToolName: tool.Name, Headers: make([]store.MCPToolParameterHeader, len(tool.ParamHeaders))}
		for j, header := range tool.ParamHeaders {
			snapshot.Headers[j] = store.MCPToolParameterHeader{ToolName: tool.Name, HeaderName: header.Name, ArgumentPath: header.ArgumentPath, Required: header.Required}
			flat = append(flat, snapshot.Headers[j])
		}
		snapshots[i] = snapshot
	}
	if !request.HasCursor && !transformed.NextCursorPresent {
		err = s.deps.MCP.Store().ReplaceMCPToolParameterHeaders(ctx, caller.UserID, caller.TenantID, resolved.Connection.ID, flat)
	} else {
		err = s.deps.MCP.Store().UpsertMCPToolParameterHeaders(ctx, caller.UserID, caller.TenantID, resolved.Connection.ID, snapshots)
	}
	if err != nil {
		return nil, err
	}
	return transformed.Body, nil
}

func (s *Server) proxyMCPToolsListSSE(w http.ResponseWriter, r *http.Request, response *http.Response, exchange *store.MCPAuditExchange, resolved *service.MCPResolvedConnection, request mcp.ClientMessage, legacy bool, sequence int64) {
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRequestBody+1))
	if err != nil || len(body) > maxRequestBody {
		s.completeMCPExchange(r.Context(), exchange, http.StatusBadGateway, "failed", 0, "response")
		writeError(w, http.StatusBadGateway, "invalid MCP upstream response.")
		return
	}
	pending := bytes.NewBuffer(body)
	events := make([][]byte, 0)
	records := make([]*store.MCPAuditMessage, 0)
	finalSeen := false
	for pending.Len() > 0 {
		event, ok := takeSSEEvent(pending)
		if !ok {
			err = errors.New("incomplete SSE event")
			break
		}
		message, hasMessage, inspectErr := mcp.InspectSSEEvent(event, s.deps.MCPAuditHMACKey)
		if inspectErr != nil {
			err = inspectErr
			break
		}
		if hasMessage && message.Kind == mcp.KindResult {
			if finalSeen {
				err = errors.New("multiple final SSE results")
				break
			}
			resultBody := sseData(event)
			if legacy {
				resultBody, inspectErr = mcp.UpgradeLegacyResponse(resultBody, request.Audit.Method)
				if inspectErr != nil {
					err = inspectErr
					break
				}
			}
			transformed, transformErr := s.transformMCPResponse(r.Context(), request, resolved, resultBody)
			if transformErr != nil {
				err = transformErr
				break
			}
			event = replaceSSEData(event, transformed)
			message, hasMessage, inspectErr = mcp.InspectSSEEvent(event, s.deps.MCPAuditHMACKey)
			if inspectErr != nil { //coverage:ignore transformed JSON is valid and SSE encoding is mechanical.
				err = inspectErr
				break
			}
			finalSeen = true
		}
		if hasMessage {
			record := mcpAuditRecord(exchange, sequence, "server_to_client", message.Kind, message.ID, message.Audit, message.ErrorCode, sseData(event), resolved.Connection.AuditMode)
			record.PolicyDecision = "allowed"
			records = append(records, record)
			sequence++
		}
		events = append(events, event)
	}
	if err != nil || !finalSeen {
		s.completeMCPExchange(r.Context(), exchange, http.StatusBadGateway, "failed", int64(len(body)), "protocol")
		writeError(w, http.StatusBadGateway, "invalid MCP upstream response.")
		return
	}
	for _, record := range records {
		if err := s.deps.MCP.Store().InsertMCPAuditMessage(r.Context(), record); err != nil {
			s.completeMCPExchange(r.Context(), exchange, http.StatusServiceUnavailable, "audit_failed", int64(len(body)), "audit")
			writeError(w, http.StatusServiceUnavailable, "MCP audit storage unavailable.")
			return
		}
	}
	w.Header().Set("Cache-Control", "private")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(response.StatusCode)
	responseBytes := int64(0)
	for _, event := range events {
		n, _ := w.Write(event)
		responseBytes += int64(n)
	}
	s.completeMCPExchange(r.Context(), exchange, response.StatusCode, "complete", responseBytes, "")
}

func replaceSSEData(event, body []byte) []byte {
	lines := strings.Split(strings.ReplaceAll(string(event), "\r\n", "\n"), "\n")
	filtered := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		if line != "" && !strings.HasPrefix(line, "data:") {
			filtered = append(filtered, line)
		}
	}
	filtered = append(filtered, "data: "+string(body), "", "")
	return []byte(strings.Join(filtered, "\n"))
}

func (s *Server) validMCPOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	want, err := url.Parse(s.deps.PublicBaseURL)
	if err != nil || want.Scheme == "" || want.Host == "" {
		return false
	}
	got, err := url.Parse(origin)
	return err == nil && strings.EqualFold(got.Scheme, want.Scheme) && strings.EqualFold(got.Host, want.Host) && got.Path == ""
}

func validMCPContentHeaders(headers http.Header) bool {
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(headers.Get("Content-Type"), ";")[0]))
	accept := strings.ToLower(headers.Get("Accept"))
	return contentType == "application/json" && strings.Contains(accept, "application/json") && strings.Contains(accept, "text/event-stream")
}

func (s *Server) proxyMCPSSE(w http.ResponseWriter, r *http.Request, response *http.Response, exchange *store.MCPAuditExchange, connection store.MCPConnection, requestMethod string, legacy bool, sequence int64) {
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(response.StatusCode)
	flusher, _ := w.(http.Flusher)
	var pending bytes.Buffer
	buf := make([]byte, 32<<10)
	total := int64(0)
	for {
		n, readErr := response.Body.Read(buf)
		if n > 0 {
			pending.Write(buf[:n])
			for {
				event, ok := takeSSEEvent(&pending)
				if !ok {
					break
				}
				total += int64(len(event))
				message, hasMessage, err := mcp.InspectSSEEvent(event, s.deps.MCPAuditHMACKey)
				if err != nil {
					s.completeMCPExchange(r.Context(), exchange, response.StatusCode, "failed", total, "protocol")
					return
				}
				if legacy && hasMessage && message.Kind == mcp.KindResult {
					upgraded, upgradeErr := mcp.UpgradeLegacyResponse(sseData(event), requestMethod)
					if upgradeErr != nil {
						s.completeMCPExchange(r.Context(), exchange, response.StatusCode, "failed", total, "protocol")
						return
					}
					event = replaceSSEData(event, upgraded)
					message, hasMessage, err = mcp.InspectSSEEvent(event, s.deps.MCPAuditHMACKey)
					if err != nil { //coverage:ignore UpgradeLegacyResponse returns a validated response.
						return
					}
				}
				if hasMessage {
					record := mcpAuditRecord(exchange, sequence, "server_to_client", message.Kind, message.ID, message.Audit, message.ErrorCode, sseData(event), connection.AuditMode)
					record.PolicyDecision = "allowed"
					if err := s.deps.MCP.Store().InsertMCPAuditMessage(r.Context(), record); err != nil {
						s.completeMCPExchange(r.Context(), exchange, response.StatusCode, "audit_failed", total, "audit")
						return
					}
					sequence++
				}
				_, _ = w.Write(event)
				if flusher != nil {
					flusher.Flush()
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) && pending.Len() == 0 {
				s.completeMCPExchange(r.Context(), exchange, response.StatusCode, "complete", total, "")
			} else {
				s.completeMCPExchange(r.Context(), exchange, response.StatusCode, "failed", total, "stream")
			}
			return
		}
	}
}

func newMCPExchange(r *http.Request, connection store.MCPConnection, accessKeyID uuid.UUID, requestBytes int64) *store.MCPAuditExchange {
	caller := contracts.CallerFrom(r.Context())
	requestID := r.Header.Get("X-Request-ID")
	remote := r.RemoteAddr
	userAgent := r.UserAgent()
	evalRunID := r.Header.Get("X-DWV-Eval-Run-ID")
	traceID := ""
	if sc := trace.SpanContextFromContext(r.Context()); sc.IsValid() {
		traceID = sc.TraceID().String()
	}
	return &store.MCPAuditExchange{ConnectionID: connection.ID, UserID: caller.UserID, TenantID: caller.TenantID,
		AccessKeyID: accessKeyID, EvalRunID: emptyStringPtr(evalRunID), DownstreamRequestID: emptyStringPtr(requestID),
		RemoteAddress: emptyStringPtr(remote), UserAgent: emptyStringPtr(userAgent), TraceID: emptyStringPtr(traceID),
		HTTPMethod: http.MethodPost, ProtocolVersion: connection.ProtocolVersion, Outcome: "started",
		StartedAt: time.Now().UTC(), RequestBytes: requestBytes}
}

func mcpAuditRecord(exchange *store.MCPAuditExchange, sequence int64, direction string, kind mcp.Kind, id mcp.ID, fields mcp.AuditFields, errorCode int, body []byte, auditMode string) *store.MCPAuditMessage {
	record := rawMCPAuditRecord(exchange, sequence, direction, string(kind), body, auditMode)
	idKind, idValue := string(id.Kind), id.Value
	record.JSONRPCIDType, record.JSONRPCIDText = &idKind, emptyStringPtr(idValue)
	record.Method, record.ToolName = emptyStringPtr(fields.Method), emptyStringPtr(fields.ToolName)
	record.ResultType, record.SubscriptionID = emptyStringPtr(fields.ResultType), emptyStringPtr(fields.SubscriptionID.Value)
	record.RequestStateDigest = decodeDigest(fields.RequestStateDigest)
	if errorCode != 0 {
		record.ErrorCode = &errorCode
	}
	return record
}

func rawMCPAuditRecord(exchange *store.MCPAuditExchange, sequence int64, direction, kind string, body []byte, auditMode string) *store.MCPAuditMessage {
	digest := sha256.Sum256(body)
	record := &store.MCPAuditMessage{ExchangeID: exchange.ID, ConnectionID: exchange.ConnectionID,
		UserID: exchange.UserID, TenantID: exchange.TenantID, SequenceNo: sequence, ObservedAt: time.Now().UTC(),
		Direction: direction, MessageKind: kind, PayloadSHA256: digest[:], PayloadBytes: int64(len(body))}
	if auditMode == "redacted" {
		payload, paths, truncated := redactMCPPayload(body)
		record.PayloadRedacted, record.RedactionPaths, record.PayloadTruncated = payload, paths, truncated
	}
	return record
}

func redactMCPPayload(body []byte) (*string, []string, bool) {
	truncated := len(body) > maxMCPAuditPayload
	if truncated {
		body = body[:maxMCPAuditPayload]
	}
	var value any
	if json.Unmarshal(body, &value) != nil {
		return nil, nil, truncated
	}
	paths := make([]string, 0)
	redactJSONValue(value, "", &paths)
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, paths, truncated
	}
	text := string(encoded)
	return &text, paths, truncated
}

func redactJSONValue(value any, path string, paths *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := path + "/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
			lower := strings.ToLower(key)
			if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "authorization") || strings.Contains(lower, "cookie") || strings.Contains(lower, "api_key") || strings.Contains(lower, "apikey") || lower == "requeststate" {
				typed[key] = audit.Redacted
				*paths = append(*paths, childPath)
				continue
			}
			redactJSONValue(child, childPath, paths)
		}
	case []any:
		for i, child := range typed {
			redactJSONValue(child, path+"/"+strconv.Itoa(i), paths)
		}
	}
}

func (s *Server) completeMCPExchange(ctx context.Context, exchange *store.MCPAuditExchange, status int, outcome string, responseBytes int64, errorClass string) {
	now := time.Now().UTC()
	exchange.CompletedAt, exchange.StatusCode, exchange.Outcome, exchange.ResponseBytes = &now, &status, outcome, responseBytes
	exchange.ErrorClass = emptyStringPtr(errorClass)
	if _, err := s.deps.MCP.Store().CompleteMCPAuditExchange(ctx, exchange); err != nil {
		s.logger.Error("MCP audit exchange completion failed", "exchange_id", exchange.ID, "err", err)
	}
}

func copyMCPRequestHeaders(dst, src http.Header) {
	for _, name := range []string{"Accept", "Content-Type", "MCP-Protocol-Version", "Mcp-Method", "Mcp-Name", "Traceparent", "Tracestate", "Baggage"} {
		for _, value := range src.Values(name) {
			dst.Add(name, value)
		}
	}
	for name, values := range src {
		if strings.HasPrefix(strings.ToLower(name), "mcp-param-") {
			for _, value := range values {
				dst.Add(name, value)
			}
		}
	}
}

func copyMCPResponseHeaders(dst, src http.Header) {
	for _, name := range []string{"Content-Type", "Cache-Control", "X-Accel-Buffering"} {
		for _, value := range src.Values(name) {
			dst.Add(name, value)
		}
	}
}

func writeMCPError(w http.ResponseWriter, status, code int, message string, id any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}})
}

func messageIDValue(id mcp.ID) any {
	if id.Kind == mcp.IDNumber {
		return json.Number(id.Value)
	}
	if id.Kind == mcp.IDString {
		return id.Value
	}
	return nil
}

func takeSSEEvent(buffer *bytes.Buffer) ([]byte, bool) {
	data := buffer.Bytes()
	index := bytes.Index(data, []byte("\n\n"))
	delimiter := 2
	if crlf := bytes.Index(data, []byte("\r\n\r\n")); crlf >= 0 && (index < 0 || crlf < index) {
		index, delimiter = crlf, 4
	}
	if index < 0 {
		return nil, false
	}
	event := append([]byte(nil), data[:index+delimiter]...)
	buffer.Next(index + delimiter)
	return event, true
}

func sseData(event []byte) []byte {
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(string(event), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "data:") {
			lines = append(lines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

func queryInt(r *http.Request, name string, fallback, minimum, maximum int) int {
	parsed, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return fallback
	}
	if parsed < minimum {
		return minimum
	}
	if parsed > maximum {
		return maximum
	}
	return parsed
}

func queryString(r *http.Request, name string) *string {
	return emptyStringPtr(r.URL.Query().Get(name))
}

func emptyStringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func decodeDigest(value string) []byte {
	if value == "" {
		return nil
	}
	return []byte(value)
}

var _ = fmt.Sprintf
