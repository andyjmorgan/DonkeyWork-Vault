// Package mcp validates and classifies MCP 2026-07-28 JSON-RPC messages.
package mcp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
)

const (
	// ProtocolVersion is the MCP revision implemented by this package.
	ProtocolVersion = "2026-07-28"
	// HeaderMismatchCode is the JSON-RPC error code assigned by the revision to mismatched HTTP metadata.
	HeaderMismatchCode = -32020
)

// Kind identifies a JSON-RPC message shape.
type Kind string

const (
	// KindRequest identifies a client request carrying an ID.
	KindRequest Kind = "request"
	// KindNotification identifies a message with a method and no ID.
	KindNotification Kind = "notification"
	// KindResult identifies a successful server response.
	KindResult Kind = "result"
	// KindError identifies a server error response.
	KindError Kind = "error"
)

// IDKind identifies how a JSON-RPC ID was represented on the wire.
type IDKind string

const (
	// IDNone means the message did not carry an ID.
	IDNone IDKind = "none"
	// IDString means the ID was a JSON string.
	IDString IDKind = "string"
	// IDNumber means the ID was a JSON number.
	IDNumber IDKind = "number"
)

// ID is an audit-safe JSON-RPC identifier that preserves its wire type.
type ID struct {
	Kind  IDKind
	Value string
}

// ClientInfo contains the self-reported MCP client identity.
type ClientInfo struct {
	Name    string
	Version string
}

// AuditFields contains protocol fields that are safe to record separately from the payload.
// RequestStateDigest is a digest only; the opaque request state is never returned.
type AuditFields struct {
	Method              string
	ToolName            string
	ResourceURI         string
	PromptName          string
	ResultType          string
	SubscriptionID      ID
	RequestStateDigest  string
	InputRequestMethods []string
}

// ClientMessage is a validated client-to-server request or notification.
type ClientMessage struct {
	Kind            Kind
	ID              ID
	ProtocolVersion string
	Client          ClientInfo
	Audit           AuditFields
	HasCursor       bool
}

// ServerMessage is a classified server-to-client notification or final response.
type ServerMessage struct {
	Kind      Kind
	ID        ID
	ErrorCode int
	Audit     AuditFields
}

// ErrorKind classifies validation failures without including untrusted values in error text.
type ErrorKind string

const (
	// ErrorInvalidJSON means the input was not exactly one JSON object.
	ErrorInvalidJSON ErrorKind = "invalid_json"
	// ErrorInvalidMessage means the object was not an allowed JSON-RPC message shape.
	ErrorInvalidMessage ErrorKind = "invalid_message"
	// ErrorHeaderMismatch means required HTTP metadata was missing, malformed, or mismatched.
	ErrorHeaderMismatch ErrorKind = "header_mismatch"
	// ErrorUnsupportedVersion means the request declared a revision this package does not implement.
	ErrorUnsupportedVersion ErrorKind = "unsupported_version"
)

// ValidationError reports a safe category and field name without echoing payload or header values.
type ValidationError struct {
	Kind  ErrorKind
	Field string
	err   error
}

// Error implements error.
func (e *ValidationError) Error() string {
	if e.Field == "" {
		return "MCP " + string(e.Kind)
	}
	return "MCP " + string(e.Kind) + ": " + e.Field
}

// Unwrap exposes the underlying parser error when one exists.
func (e *ValidationError) Unwrap() error { return e.err }

// IsErrorKind reports whether err is an MCP validation error of kind.
func IsErrorKind(err error, kind ErrorKind) bool {
	var target *ValidationError
	return errors.As(err, &target) && target.Kind == kind
}

// Options controls sensitive digesting and recognized parameter-header validation.
type Options struct {
	// RequestStateHMACKey enables a non-reversible keyed digest. An empty key falls back to SHA-256.
	RequestStateHMACKey []byte
	ParamHeaders        []ParamHeader
}

// InspectClient validates one client JSON-RPC message and its MCP HTTP headers.
func InspectClient(body []byte, headers http.Header, opts Options) (ClientMessage, error) {
	obj, err := decodeObject(body)
	if err != nil {
		return ClientMessage{}, err
	}
	if err := validateBase(obj); err != nil {
		return ClientMessage{}, err
	}
	if _, ok := obj["result"]; ok {
		return ClientMessage{}, invalidMessage("result", nil)
	}
	if _, ok := obj["error"]; ok {
		return ClientMessage{}, invalidMessage("error", nil)
	}
	method, err := requiredString(obj, "method")
	if err != nil || method == "" {
		return ClientMessage{}, invalidMessage("method", err)
	}

	id, hasID, err := parseOptionalID(obj)
	if err != nil {
		return ClientMessage{}, err
	}
	kind := KindNotification
	if hasID {
		kind = KindRequest
	}

	params, hasParams, err := optionalObject(obj, "params")
	if err != nil {
		return ClientMessage{}, err
	}
	meta := map[string]json.RawMessage{}
	if hasParams {
		meta, _, err = optionalObject(params, "_meta")
		if err != nil {
			return ClientMessage{}, err
		}
	}

	version, client, err := parseRequestMetadata(meta, kind)
	if err != nil {
		return ClientMessage{}, err
	}
	if version != ProtocolVersion {
		return ClientMessage{}, &ValidationError{Kind: ErrorUnsupportedVersion, Field: "params._meta.protocolVersion"}
	}
	audit := extractRequestAudit(method, params, opts.RequestStateHMACKey)
	_, hasCursor := params["cursor"]
	message := ClientMessage{Kind: kind, ID: id, ProtocolVersion: version, Client: client, Audit: audit, HasCursor: hasCursor}
	if err := validateHeaders(headers, method, version, params, opts.ParamHeaders); err != nil {
		return ClientMessage{}, err
	}
	return message, nil
}

// InspectServer validates and classifies one server JSON-RPC notification or final response.
func InspectServer(body []byte, requestStateHMACKey []byte) (ServerMessage, error) {
	obj, err := decodeObject(body)
	if err != nil {
		return ServerMessage{}, err
	}
	if err := validateBase(obj); err != nil {
		return ServerMessage{}, err
	}
	id, hasID, err := parseOptionalID(obj)
	if err != nil {
		return ServerMessage{}, err
	}
	methodRaw, hasMethod := obj["method"]
	resultRaw, hasResult := obj["result"]
	errorRaw, hasError := obj["error"]

	switch {
	case hasMethod && !hasID && !hasResult && !hasError:
		method, err := rawString(methodRaw)
		if err != nil || method == "" {
			return ServerMessage{}, invalidMessage("method", err)
		}
		params, _, err := optionalObject(obj, "params")
		if err != nil {
			return ServerMessage{}, err
		}
		return ServerMessage{Kind: KindNotification, Audit: extractNotificationAudit(method, params)}, nil
	case !hasMethod && hasID && hasResult && !hasError:
		result, err := rawObject(resultRaw, "result")
		if err != nil {
			return ServerMessage{}, err
		}
		return ServerMessage{Kind: KindResult, ID: id, Audit: extractResultAudit(result, requestStateHMACKey)}, nil
	case !hasMethod && !hasResult && hasError:
		errorObject, err := rawObject(errorRaw, "error")
		if err != nil {
			return ServerMessage{}, err
		}
		code, err := requiredInteger(errorObject, "code")
		if err != nil {
			return ServerMessage{}, invalidMessage("error.code", err)
		}
		if _, err := requiredString(errorObject, "message"); err != nil {
			return ServerMessage{}, invalidMessage("error.message", err)
		}
		return ServerMessage{Kind: KindError, ID: id, ErrorCode: code}, nil
	default:
		return ServerMessage{}, invalidMessage("shape", nil)
	}
}

func decodeObject(body []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, &ValidationError{Kind: ErrorInvalidJSON, err: err}
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err == nil {
		return nil, &ValidationError{Kind: ErrorInvalidJSON}
	} else if !errors.Is(err, io.EOF) {
		return nil, &ValidationError{Kind: ErrorInvalidJSON, err: err}
	}
	return rawObject(raw, "message")
}

func rawObject(raw json.RawMessage, field string) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, invalidMessage(field, nil)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, invalidMessage(field, err)
	}
	return obj, nil
}

func validateBase(obj map[string]json.RawMessage) error {
	version, err := requiredString(obj, "jsonrpc")
	if err != nil || version != "2.0" {
		return invalidMessage("jsonrpc", err)
	}
	return nil
}

func parseOptionalID(obj map[string]json.RawMessage) (ID, bool, error) {
	raw, ok := obj["id"]
	if !ok {
		return ID{Kind: IDNone}, false, nil
	}
	if len(raw) == 0 {
		return ID{}, false, invalidMessage("id", nil)
	}
	if raw[0] == '"' {
		value, err := rawString(raw)
		if err != nil {
			return ID{}, false, invalidMessage("id", err)
		}
		return ID{Kind: IDString, Value: value}, true, nil
	}
	if raw[0] != '-' && (raw[0] < '0' || raw[0] > '9') {
		return ID{}, false, invalidMessage("id", nil)
	}
	var number json.Number
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&number); err != nil {
		return ID{}, false, invalidMessage("id", err)
	}
	return ID{Kind: IDNumber, Value: number.String()}, true, nil
}

func parseRequestMetadata(meta map[string]json.RawMessage, kind Kind) (string, ClientInfo, error) {
	version, err := requiredString(meta, "io.modelcontextprotocol/protocolVersion")
	if err != nil {
		return "", ClientInfo{}, invalidMessage("params._meta.protocolVersion", err)
	}
	if kind == KindRequest {
		if _, ok, err := optionalObject(meta, "io.modelcontextprotocol/clientCapabilities"); err != nil || !ok {
			return "", ClientInfo{}, invalidMessage("params._meta.clientCapabilities", err)
		}
	}
	clientObject, ok, err := optionalObject(meta, "io.modelcontextprotocol/clientInfo")
	if err != nil {
		return "", ClientInfo{}, invalidMessage("params._meta.clientInfo", err)
	}
	if !ok {
		return version, ClientInfo{}, nil
	}
	name, nameErr := requiredString(clientObject, "name")
	clientVersion, versionErr := requiredString(clientObject, "version")
	if nameErr != nil || versionErr != nil || name == "" || clientVersion == "" {
		return "", ClientInfo{}, invalidMessage("params._meta.clientInfo", errors.Join(nameErr, versionErr))
	}
	return version, ClientInfo{Name: name, Version: clientVersion}, nil
}

func extractRequestAudit(method string, params map[string]json.RawMessage, digestKey []byte) AuditFields {
	audit := AuditFields{Method: method, SubscriptionID: ID{Kind: IDNone}}
	switch method {
	case "tools/call":
		audit.ToolName, _ = optionalString(params, "name")
	case "resources/read":
		audit.ResourceURI, _ = optionalString(params, "uri")
	case "prompts/get":
		audit.PromptName, _ = optionalString(params, "name")
	}
	if state, ok := optionalString(params, "requestState"); ok {
		audit.RequestStateDigest = digestState(state, digestKey)
	}
	return audit
}

func extractNotificationAudit(method string, params map[string]json.RawMessage) AuditFields {
	audit := AuditFields{Method: method, SubscriptionID: ID{Kind: IDNone}}
	meta, _, _ := optionalObject(params, "_meta")
	if id, ok, _ := parseOptionalID(map[string]json.RawMessage{"id": meta["io.modelcontextprotocol/subscriptionId"]}); ok {
		audit.SubscriptionID = id
	}
	return audit
}

func extractResultAudit(result map[string]json.RawMessage, digestKey []byte) AuditFields {
	audit := AuditFields{SubscriptionID: ID{Kind: IDNone}}
	audit.ResultType, _ = optionalString(result, "resultType")
	if state, ok := optionalString(result, "requestState"); ok {
		audit.RequestStateDigest = digestState(state, digestKey)
	}
	requests, ok, _ := optionalObject(result, "inputRequests")
	if ok {
		for _, raw := range requests {
			request, err := rawObject(raw, "inputRequest")
			if err != nil {
				continue
			}
			if method, ok := optionalString(request, "method"); ok {
				audit.InputRequestMethods = append(audit.InputRequestMethods, method)
			}
		}
		sort.Strings(audit.InputRequestMethods)
	}
	return audit
}

func digestState(state string, key []byte) string {
	if len(key) == 0 {
		sum := sha256.Sum256([]byte(state))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write([]byte(state))
	return "hmac-sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func requiredString(obj map[string]json.RawMessage, field string) (string, error) {
	raw, ok := obj[field]
	if !ok {
		return "", errors.New("missing field")
	}
	return rawString(raw)
}

func optionalString(obj map[string]json.RawMessage, field string) (string, bool) {
	raw, ok := obj[field]
	if !ok {
		return "", false
	}
	value, err := rawString(raw)
	return value, err == nil
}

func rawString(raw json.RawMessage) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	return value, nil
}

func optionalObject(obj map[string]json.RawMessage, field string) (map[string]json.RawMessage, bool, error) {
	raw, ok := obj[field]
	if !ok {
		return map[string]json.RawMessage{}, false, nil
	}
	value, err := rawObject(raw, field)
	return value, true, err
}

func requiredInteger(obj map[string]json.RawMessage, field string) (int, error) {
	raw, ok := obj[field]
	if !ok {
		return 0, errors.New("missing field")
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, err
	}
	return value, nil
}

func invalidMessage(field string, err error) error {
	return &ValidationError{Kind: ErrorInvalidMessage, Field: field, err: err}
}
