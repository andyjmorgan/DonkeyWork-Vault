package mcp

import (
	"encoding/json"
	"mime"
	"net/http"
	"sort"
	"strings"
)

// ProbeClass describes the protocol era inferred from an active server/discover probe.
type ProbeClass string

const (
	// ProbeModern202607 identifies a valid July 2026 server/discover response.
	ProbeModern202607 ProbeClass = "modern_2026_07"
	// ProbeLegacySessionLikely identifies evidence of a pre-July initialization/session protocol.
	ProbeLegacySessionLikely ProbeClass = "legacy_session_likely"
	// ProbeAuthRequired identifies an upstream authorization challenge.
	ProbeAuthRequired ProbeClass = "auth_required"
	// ProbeUnavailable identifies an upstream HTTP server failure.
	ProbeUnavailable ProbeClass = "unavailable"
	// ProbeIncompatible identifies a responding endpoint that did not produce compatible MCP.
	ProbeIncompatible ProbeClass = "incompatible"
	// ProbeUnknown means the response did not provide enough protocol evidence.
	ProbeUnknown ProbeClass = "unknown"
)

// ProbeReason is a safe explanation that never includes upstream response content.
type ProbeReason string

const (
	// ProbeReasonDiscoveryValid means a strict July 2026 discovery result was received.
	ProbeReasonDiscoveryValid ProbeReason = "discovery_valid"
	// ProbeReasonAuthorizationStatus means HTTP 401 or 403 was received.
	ProbeReasonAuthorizationStatus ProbeReason = "authorization_status"
	// ProbeReasonServerFailure means an HTTP 5xx response was received.
	ProbeReasonServerFailure ProbeReason = "server_failure"
	// ProbeReasonMethodNotFound means server/discover returned JSON-RPC method-not-found.
	ProbeReasonMethodNotFound ProbeReason = "method_not_found"
	// ProbeReasonLegacyVersion means the response advertised only pre-July protocol versions.
	ProbeReasonLegacyVersion ProbeReason = "legacy_version"
	// ProbeReasonLegacySession means legacy initialize or session wording appeared in a JSON-RPC error.
	ProbeReasonLegacySession ProbeReason = "legacy_session"
	// ProbeReasonModernError means a recognized modern July protocol error was received.
	ProbeReasonModernError ProbeReason = "modern_error"
	// ProbeReasonMalformedSuccess means a 2xx response was not a valid discovery result.
	ProbeReasonMalformedSuccess ProbeReason = "malformed_success"
	// ProbeReasonUnexpectedContent means a non-JSON success response was received.
	ProbeReasonUnexpectedContent ProbeReason = "unexpected_content"
	// ProbeReasonRedirect means an HTTP redirect was received.
	ProbeReasonRedirect ProbeReason = "redirect"
	// ProbeReasonNotFound means an unstructured HTTP 404 was received.
	ProbeReasonNotFound ProbeReason = "not_found"
	// ProbeReasonHTTPStatus means another HTTP status lacked protocol evidence.
	ProbeReasonHTTPStatus ProbeReason = "http_status"
	// ProbeReasonMismatchedID means a discovery response used a different JSON-RPC ID.
	ProbeReasonMismatchedID ProbeReason = "mismatched_id"
	// ProbeReasonNetworkFailure means the upstream request failed before an HTTP response arrived.
	ProbeReasonNetworkFailure ProbeReason = "network_failure"
	// ProbeReasonResponseTooLarge means the upstream response exceeded the gateway inspection bound.
	ProbeReasonResponseTooLarge ProbeReason = "response_too_large"
	// ProbeReasonAuthorizationUnavailable means configured upstream OAuth could not supply a token.
	ProbeReasonAuthorizationUnavailable ProbeReason = "authorization_unavailable"
)

// ProbeInput is the completed HTTP response from a July server/discover request.
type ProbeInput struct {
	StatusCode  int
	ContentType string
	Body        []byte
	RequestID   ID
}

// ProbeResult is an audit-safe protocol-era classification and validated discovery metadata.
type ProbeResult struct {
	Class             ProbeClass
	Reason            ProbeReason
	SupportedVersions []string
	Capabilities      []Capability
	Server            ClientInfo
}

// ClassifyProbe classifies the HTTP response to an active July server/discover probe.
func ClassifyProbe(input ProbeInput) ProbeResult {
	if input.StatusCode == http.StatusUnauthorized || input.StatusCode == http.StatusForbidden {
		return ProbeResult{Class: ProbeAuthRequired, Reason: ProbeReasonAuthorizationStatus}
	}
	if input.StatusCode >= 500 && input.StatusCode <= 599 {
		return ProbeResult{Class: ProbeUnavailable, Reason: ProbeReasonServerFailure}
	}
	if input.StatusCode >= 300 && input.StatusCode <= 399 {
		return ProbeResult{Class: ProbeUnknown, Reason: ProbeReasonRedirect}
	}

	jsonContent := isJSONContentType(input.ContentType)
	object, decodeErr := decodeObject(input.Body)
	if decodeErr == nil {
		if errorResult, ok := classifyProbeError(object, input.RequestID); ok {
			return errorResult
		}
		if input.StatusCode >= 200 && input.StatusCode <= 299 {
			return classifyProbeDiscovery(object, input.RequestID)
		}
	}
	if input.StatusCode >= 200 && input.StatusCode <= 299 {
		if !jsonContent {
			return ProbeResult{Class: ProbeIncompatible, Reason: ProbeReasonUnexpectedContent}
		}
		return ProbeResult{Class: ProbeIncompatible, Reason: ProbeReasonMalformedSuccess}
	}
	if input.StatusCode == http.StatusNotFound {
		return ProbeResult{Class: ProbeUnknown, Reason: ProbeReasonNotFound}
	}
	return ProbeResult{Class: ProbeUnknown, Reason: ProbeReasonHTTPStatus}
}

func classifyProbeDiscovery(envelope map[string]json.RawMessage, requestID ID) ProbeResult {
	if err := validateBase(envelope); err != nil {
		return ProbeResult{Class: ProbeIncompatible, Reason: ProbeReasonMalformedSuccess}
	}
	id, hasID, err := parseOptionalID(envelope)
	if err != nil || !hasID || !probeIDsEqual(id, requestID) {
		return ProbeResult{Class: ProbeIncompatible, Reason: ProbeReasonMismatchedID}
	}
	if _, hasMethod := envelope["method"]; hasMethod {
		return ProbeResult{Class: ProbeIncompatible, Reason: ProbeReasonMalformedSuccess}
	}
	result, ok, err := optionalObject(envelope, "result")
	if err != nil || !ok || validateCacheableResult(result) != nil {
		return ProbeResult{Class: ProbeIncompatible, Reason: ProbeReasonMalformedSuccess}
	}
	versions, err := requiredStringArray(result, "supportedVersions")
	if err != nil || !containsString(versions, ProtocolVersion) {
		if len(versions) > 0 && allLegacyVersions(versions) {
			return ProbeResult{Class: ProbeLegacySessionLikely, Reason: ProbeReasonLegacyVersion, SupportedVersions: versions}
		}
		return ProbeResult{Class: ProbeIncompatible, Reason: ProbeReasonMalformedSuccess}
	}
	capabilities, ok, err := optionalObject(result, "capabilities")
	if err != nil || !ok {
		return ProbeResult{Class: ProbeIncompatible, Reason: ProbeReasonMalformedSuccess}
	}
	parsedCapabilities, err := probeCapabilities(capabilities)
	if err != nil {
		return ProbeResult{Class: ProbeIncompatible, Reason: ProbeReasonMalformedSuccess}
	}
	server := probeServerInfo(result)
	return ProbeResult{
		Class: ProbeModern202607, Reason: ProbeReasonDiscoveryValid, SupportedVersions: versions,
		Capabilities: parsedCapabilities, Server: server,
	}
}

func classifyProbeError(envelope map[string]json.RawMessage, requestID ID) (ProbeResult, bool) {
	if validateBase(envelope) != nil {
		return ProbeResult{}, false
	}
	errorObject, ok, err := optionalObject(envelope, "error")
	if err != nil || !ok {
		return ProbeResult{}, false
	}
	id, hasID, idErr := parseOptionalID(envelope)
	if idErr != nil || hasID && !probeIDsEqual(id, requestID) {
		return ProbeResult{Class: ProbeUnknown, Reason: ProbeReasonMismatchedID}, true
	}
	code, codeErr := requiredInteger(errorObject, "code")
	if codeErr != nil {
		return ProbeResult{}, false
	}
	if code == -32601 {
		return ProbeResult{Class: ProbeLegacySessionLikely, Reason: ProbeReasonMethodNotFound}, true
	}
	if code == -32022 {
		versions := probeSupportedVersions(errorObject)
		class, reason := ProbeUnknown, ProbeReasonModernError
		if len(versions) > 0 && allLegacyVersions(versions) {
			class, reason = ProbeLegacySessionLikely, ProbeReasonLegacyVersion
		}
		return ProbeResult{Class: class, Reason: reason, SupportedVersions: versions}, true
	}
	if code == HeaderMismatchCode || code == -32602 {
		return ProbeResult{Class: ProbeUnknown, Reason: ProbeReasonModernError}, true
	}
	message, _ := optionalString(errorObject, "message")
	normalized := strings.ToLower(message)
	if strings.Contains(normalized, "initialize") || strings.Contains(normalized, "session") || strings.Contains(normalized, "mcp-session-id") {
		return ProbeResult{Class: ProbeLegacySessionLikely, Reason: ProbeReasonLegacySession}, true
	}
	return ProbeResult{}, false
}

func probeCapabilities(object map[string]json.RawMessage) ([]Capability, error) {
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	sort.Strings(names)
	capabilities := make([]Capability, 0, len(object))
	for _, name := range names {
		if !validCapabilityName(name) {
			return nil, transformError("result.capabilities")
		}
		settings, err := rawObject(object[name], "capability")
		if err != nil {
			return nil, transformError("result.capabilities")
		}
		encoded, err := json.Marshal(settings)
		if err != nil { //coverage:ignore settings came from valid JSON.
			return nil, transformError("result.capabilities")
		}
		capabilities = append(capabilities, Capability{Name: name, Settings: encoded})
	}
	return capabilities, nil
}

func probeServerInfo(result map[string]json.RawMessage) ClientInfo {
	meta, ok, _ := optionalObject(result, "_meta")
	if !ok {
		return ClientInfo{}
	}
	server, ok, _ := optionalObject(meta, "io.modelcontextprotocol/serverInfo")
	if !ok {
		return ClientInfo{}
	}
	name, nameOK := optionalString(server, "name")
	version, versionOK := optionalString(server, "version")
	if !nameOK || !versionOK || name == "" || version == "" {
		return ClientInfo{}
	}
	return ClientInfo{Name: name, Version: version}
}

func probeSupportedVersions(errorObject map[string]json.RawMessage) []string {
	data, ok, _ := optionalObject(errorObject, "data")
	if !ok {
		return nil
	}
	versions, _ := requiredStringArray(data, "supported")
	return versions
}

func requiredStringArray(object map[string]json.RawMessage, field string) ([]string, error) {
	raw, ok := object[field]
	if !ok {
		return nil, transformError(field)
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return nil, transformErrorWithCause(field, err)
	}
	for _, value := range values {
		if value == "" {
			return nil, transformError(field)
		}
	}
	return values, nil
}

func isJSONContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	mediaType = strings.ToLower(mediaType)
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func probeIDsEqual(left, right ID) bool {
	return left.Kind == right.Kind && left.Value == right.Value
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func allLegacyVersions(versions []string) bool {
	if len(versions) == 0 {
		return false
	}
	for _, version := range versions {
		if version >= ProtocolVersion || len(version) != len(ProtocolVersion) {
			return false
		}
	}
	return true
}
