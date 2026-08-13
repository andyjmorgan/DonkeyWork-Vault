package mcp

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// PrimitiveType is a JSON primitive supported by x-mcp-header.
type PrimitiveType string

const (
	// PrimitiveString is a JSON string.
	PrimitiveString PrimitiveType = "string"
	// PrimitiveInteger is a JSON integer within the JavaScript-safe range.
	PrimitiveInteger PrimitiveType = "integer"
	// PrimitiveBoolean is a JSON boolean.
	PrimitiveBoolean PrimitiveType = "boolean"
)

// ParamHeaderDefinition is a validated x-mcp-header annotation from a tool schema.
type ParamHeaderDefinition struct {
	Name         string
	ArgumentPath []string
	Required     bool
	Type         PrimitiveType
}

// ToolDefinition contains policy and transport metadata for an accepted tool.
type ToolDefinition struct {
	Name         string
	ParamHeaders []ParamHeaderDefinition
}

// ExcludedTool explains an omitted invalid or disallowed tool without retaining its schema.
type ExcludedTool struct {
	Index  int
	Name   string
	Reason string
}

// ToolAllowFunc decides whether an otherwise valid tool is visible to the caller.
type ToolAllowFunc func(name string) bool

// ToolsListTransformation is a policy-filtered tools/list response and its validated definitions.
type ToolsListTransformation struct {
	Body              []byte
	Tools             []ToolDefinition
	Excluded          []ExcludedTool
	Filtered          bool
	NextCursorPresent bool
}

// TransformToolsList validates and filters a July 2026 tools/list result response.
// Invalid tools are excluded individually; an invalid response envelope returns an error.
func TransformToolsList(body []byte, allow ToolAllowFunc) (ToolsListTransformation, error) {
	envelope, result, err := parseResultEnvelope(body)
	if err != nil {
		return ToolsListTransformation{}, err
	}
	if err := validateCacheableResult(result); err != nil {
		return ToolsListTransformation{}, err
	}
	toolsRaw, ok := result["tools"]
	if !ok || len(toolsRaw) == 0 || toolsRaw[0] != '[' {
		return ToolsListTransformation{}, transformError("result.tools")
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(toolsRaw, &tools); err != nil {
		return ToolsListTransformation{}, transformErrorWithCause("result.tools", err)
	}

	acceptedRaw := make([]json.RawMessage, 0, len(tools))
	transformed := ToolsListTransformation{}
	_, transformed.NextCursorPresent = result["nextCursor"]
	transformed.Tools = make([]ToolDefinition, 0, len(tools))
	seenNames := make(map[string]struct{}, len(tools))
	for index, raw := range tools {
		definition, err := parseToolDefinition(raw)
		if err != nil {
			transformed.Excluded = append(transformed.Excluded, ExcludedTool{Index: index, Reason: errorField(err)})
			continue
		}
		if _, duplicate := seenNames[definition.Name]; duplicate {
			transformed.Excluded = append(transformed.Excluded, ExcludedTool{Index: index, Name: definition.Name, Reason: "duplicate_name"})
			continue
		}
		seenNames[definition.Name] = struct{}{}
		if allow != nil && !allow(definition.Name) {
			transformed.Excluded = append(transformed.Excluded, ExcludedTool{Index: index, Name: definition.Name, Reason: "policy"})
			continue
		}
		acceptedRaw = append(acceptedRaw, raw)
		transformed.Tools = append(transformed.Tools, definition)
	}
	transformed.Filtered = len(acceptedRaw) != len(tools)
	encodedTools, err := json.Marshal(acceptedRaw)
	if err != nil { //coverage:ignore acceptedRaw contains already-valid JSON values.
		return ToolsListTransformation{}, transformErrorWithCause("result.tools", err)
	}
	result["tools"] = encodedTools
	if transformed.Filtered || allow != nil {
		result["cacheScope"] = json.RawMessage(`"private"`)
	}
	transformed.Body, err = encodeResultEnvelope(envelope, result)
	if err != nil { //coverage:ignore envelope and result contain already-valid JSON values.
		return ToolsListTransformation{}, err
	}
	return transformed, nil
}

func parseToolDefinition(raw json.RawMessage) (ToolDefinition, error) {
	tool, err := rawObject(raw, "tool")
	if err != nil {
		return ToolDefinition{}, transformError("tool")
	}
	name, err := requiredString(tool, "name")
	if err != nil || name == "" || len(name) > 128 {
		return ToolDefinition{}, transformErrorWithCause("tool.name", err)
	}
	schemaRaw, ok := tool["inputSchema"]
	if !ok {
		return ToolDefinition{}, transformError("tool.inputSchema")
	}
	schema, err := rawObject(schemaRaw, "inputSchema")
	if err != nil {
		return ToolDefinition{}, transformError("tool.inputSchema")
	}
	typeName, err := requiredString(schema, "type")
	if err != nil || typeName != "object" {
		return ToolDefinition{}, transformErrorWithCause("tool.inputSchema.type", err)
	}
	headers, err := extractParamHeaderDefinitions(schema)
	if err != nil {
		return ToolDefinition{}, err
	}
	return ToolDefinition{Name: name, ParamHeaders: headers}, nil
}

func extractParamHeaderDefinitions(root map[string]json.RawMessage) ([]ParamHeaderDefinition, error) {
	definitions := make([]ParamHeaderDefinition, 0)
	seen := make(map[string]struct{})
	if err := inspectSchemaNode(root, nil, true, true, seen, &definitions); err != nil {
		return nil, err
	}
	return definitions, nil
}

func inspectSchemaNode(node map[string]json.RawMessage, path []string, reachable, requiredPath bool, seen map[string]struct{}, definitions *[]ParamHeaderDefinition) error {
	if annotation, exists := node["x-mcp-header"]; exists {
		if !reachable || len(path) == 0 {
			return transformError("tool.inputSchema.x-mcp-header.unreachable")
		}
		name, err := rawString(annotation)
		if err != nil || !validToken(name) {
			return transformErrorWithCause("tool.inputSchema.x-mcp-header.name", err)
		}
		folded := strings.ToLower(name)
		if _, duplicate := seen[folded]; duplicate {
			return transformError("tool.inputSchema.x-mcp-header.duplicate")
		}
		seen[folded] = struct{}{}
		typeName, err := requiredString(node, "type")
		primitive := PrimitiveType(typeName)
		if err != nil || primitive != PrimitiveString && primitive != PrimitiveInteger && primitive != PrimitiveBoolean {
			return transformErrorWithCause("tool.inputSchema.x-mcp-header.type", err)
		}
		*definitions = append(*definitions, ParamHeaderDefinition{Name: name, ArgumentPath: append([]string(nil), path...), Required: requiredPath, Type: primitive})
	}

	required, err := schemaRequiredNames(node)
	if err != nil {
		return err
	}
	properties, hasProperties, err := optionalObject(node, "properties")
	if err != nil {
		return transformError("tool.inputSchema.properties")
	}
	if hasProperties {
		propertyNames := make([]string, 0, len(properties))
		for name := range properties {
			propertyNames = append(propertyNames, name)
		}
		sort.Strings(propertyNames)
		for _, name := range propertyNames {
			child, err := rawObject(properties[name], "property")
			if err != nil {
				return transformError("tool.inputSchema.property")
			}
			_, isRequired := required[name]
			if err := inspectSchemaNode(child, append(path, name), reachable, requiredPath && isRequired, seen, definitions); err != nil {
				return err
			}
		}
	}
	return inspectUnreachableAnnotations(node, map[string]struct{}{"properties": {}, "x-mcp-header": {}}, seen, definitions)
}

func inspectUnreachableAnnotations(node map[string]json.RawMessage, skip map[string]struct{}, seen map[string]struct{}, definitions *[]ParamHeaderDefinition) error {
	for key, raw := range node {
		if _, omitted := skip[key]; omitted {
			continue
		}
		if err := inspectArbitrarySchema(raw, seen, definitions); err != nil {
			return err
		}
	}
	return nil
}

func inspectArbitrarySchema(raw json.RawMessage, seen map[string]struct{}, definitions *[]ParamHeaderDefinition) error {
	if len(raw) == 0 {
		return nil
	}
	if raw[0] == '{' {
		object, err := rawObject(raw, "schema")
		if err != nil {
			return transformError("tool.inputSchema")
		}
		return inspectSchemaNode(object, nil, false, false, seen, definitions)
	}
	if raw[0] == '[' {
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return transformErrorWithCause("tool.inputSchema", err)
		}
		for _, value := range values {
			if err := inspectArbitrarySchema(value, seen, definitions); err != nil {
				return err
			}
		}
	}
	return nil
}

func schemaRequiredNames(node map[string]json.RawMessage) (map[string]struct{}, error) {
	names := make(map[string]struct{})
	raw, ok := node["required"]
	if !ok {
		return names, nil
	}
	var required []string
	if err := json.Unmarshal(raw, &required); err != nil {
		return nil, transformErrorWithCause("tool.inputSchema.required", err)
	}
	for _, name := range required {
		names[name] = struct{}{}
	}
	return names, nil
}

func parseResultEnvelope(body []byte) (map[string]json.RawMessage, map[string]json.RawMessage, error) {
	envelope, err := decodeObject(body)
	if err != nil {
		return nil, nil, transformErrorWithCause("response", err)
	}
	if err := validateBase(envelope); err != nil {
		return nil, nil, transformErrorWithCause("response.jsonrpc", err)
	}
	if _, hasID, err := parseOptionalID(envelope); err != nil || !hasID {
		return nil, nil, transformErrorWithCause("response.id", err)
	}
	if _, hasError := envelope["error"]; hasError {
		return nil, nil, transformError("response.error")
	}
	if _, hasMethod := envelope["method"]; hasMethod {
		return nil, nil, transformError("response.method")
	}
	result, ok, err := optionalObject(envelope, "result")
	if err != nil || !ok {
		return nil, nil, transformErrorWithCause("response.result", err)
	}
	return envelope, result, nil
}

func validateCacheableResult(result map[string]json.RawMessage) error {
	resultType, err := requiredString(result, "resultType")
	if err != nil || resultType != "complete" {
		return transformErrorWithCause("result.resultType", err)
	}
	var ttl float64
	if raw, ok := result["ttlMs"]; !ok || json.Unmarshal(raw, &ttl) != nil || ttl < 0 {
		return transformError("result.ttlMs")
	}
	cacheScope, err := requiredString(result, "cacheScope")
	if err != nil || cacheScope != "public" && cacheScope != "private" {
		return transformErrorWithCause("result.cacheScope", err)
	}
	return nil
}

func encodeResultEnvelope(envelope, result map[string]json.RawMessage) ([]byte, error) {
	encodedResult, err := json.Marshal(result)
	if err != nil {
		return nil, transformErrorWithCause("response.result", err)
	}
	envelope["result"] = encodedResult
	body, err := json.Marshal(envelope)
	if err != nil {
		return nil, transformErrorWithCause("response", err)
	}
	return body, nil
}

// TransformError reports only the structural field that failed validation.
type TransformError struct {
	Field string
	err   error
}

// Error implements error without echoing untrusted response values.
func (e *TransformError) Error() string { return "invalid MCP transformation input: " + e.Field }

// Unwrap exposes the underlying syntax or type error.
func (e *TransformError) Unwrap() error { return e.err }

func transformError(field string) error { return &TransformError{Field: field} }

func transformErrorWithCause(field string, err error) error {
	return &TransformError{Field: field, err: err}
}

func errorField(err error) string {
	var target *TransformError
	if errors.As(err, &target) {
		return target.Field
	}
	return "tool"
}

// HeaderBindings converts extracted definitions to the request validator's binding type.
func (tool ToolDefinition) HeaderBindings() []ParamHeader {
	bindings := make([]ParamHeader, len(tool.ParamHeaders))
	for index, definition := range tool.ParamHeaders {
		bindings[index] = ParamHeader{Name: definition.Name, ArgumentPath: append([]string(nil), definition.ArgumentPath...), Required: definition.Required}
	}
	return bindings
}

// GatewayIdentity is the server identity advertised by the MCP gateway.
type GatewayIdentity struct {
	Name        string
	Version     string
	Description string
	WebsiteURL  string
}

// Capability is one top-level July 2026 server capability and its settings object.
type Capability struct {
	Name     string
	Settings json.RawMessage
}

// CapabilityAllowFunc decides whether an upstream capability is advertised downstream.
type CapabilityAllowFunc func(name string) bool

// DiscoverTransformation is a policy-limited server/discover response and capability inventory.
type DiscoverTransformation struct {
	Body         []byte
	Capabilities []Capability
	Filtered     bool
}

// TransformDiscover replaces upstream identity with gateway identity and filters capabilities.
func TransformDiscover(body []byte, identity GatewayIdentity, allow CapabilityAllowFunc) (DiscoverTransformation, error) {
	if err := validateGatewayIdentity(identity); err != nil {
		return DiscoverTransformation{}, err
	}
	envelope, result, err := parseResultEnvelope(body)
	if err != nil {
		return DiscoverTransformation{}, err
	}
	if err := validateCacheableResult(result); err != nil {
		return DiscoverTransformation{}, err
	}
	capabilities, ok, err := optionalObject(result, "capabilities")
	if err != nil || !ok {
		return DiscoverTransformation{}, transformErrorWithCause("result.capabilities", err)
	}

	names := make([]string, 0, len(capabilities))
	for name := range capabilities {
		names = append(names, name)
	}
	sort.Strings(names)
	filtered := make(map[string]json.RawMessage, len(capabilities))
	transformed := DiscoverTransformation{Capabilities: make([]Capability, 0, len(capabilities))}
	for _, name := range names {
		settings, err := rawObject(capabilities[name], "capability")
		if err != nil || !validCapabilityName(name) {
			return DiscoverTransformation{}, transformErrorWithCause("result.capabilities", err)
		}
		if allow != nil && !allow(name) {
			transformed.Filtered = true
			continue
		}
		encoded, err := json.Marshal(settings)
		if err != nil { //coverage:ignore settings came from valid JSON.
			return DiscoverTransformation{}, transformErrorWithCause("result.capabilities", err)
		}
		filtered[name] = encoded
		transformed.Capabilities = append(transformed.Capabilities, Capability{Name: name, Settings: append(json.RawMessage(nil), encoded...)})
	}
	encodedCapabilities, err := json.Marshal(filtered)
	if err != nil { //coverage:ignore filtered contains already-valid JSON values.
		return DiscoverTransformation{}, transformErrorWithCause("result.capabilities", err)
	}
	result["capabilities"] = encodedCapabilities
	result["supportedVersions"] = json.RawMessage(`["` + ProtocolVersion + `"]`)
	result["_meta"], err = gatewayMeta(identity)
	if err != nil { //coverage:ignore validated identity is always JSON encodable.
		return DiscoverTransformation{}, err
	}
	if transformed.Filtered {
		result["cacheScope"] = json.RawMessage(`"private"`)
	}
	transformed.Body, err = encodeResultEnvelope(envelope, result)
	if err != nil { //coverage:ignore envelope and result contain valid JSON values.
		return DiscoverTransformation{}, err
	}
	return transformed, nil
}

// BuildDiscover constructs a local July 2026 server/discover result response.
func BuildDiscover(id ID, identity GatewayIdentity, capabilities []Capability, ttlMS int64) ([]byte, error) {
	if err := validateGatewayIdentity(identity); err != nil {
		return nil, err
	}
	if id.Kind != IDString && id.Kind != IDNumber || id.Value == "" {
		return nil, transformError("response.id")
	}
	if ttlMS < 0 {
		return nil, transformError("result.ttlMs")
	}
	capabilityObject := make(map[string]json.RawMessage, len(capabilities))
	for _, capability := range capabilities {
		if !validCapabilityName(capability.Name) {
			return nil, transformError("result.capabilities.name")
		}
		if _, duplicate := capabilityObject[capability.Name]; duplicate {
			return nil, transformError("result.capabilities.duplicate")
		}
		settings, err := rawObject(capability.Settings, "capability")
		if err != nil {
			return nil, transformError("result.capabilities.settings")
		}
		encoded, err := json.Marshal(settings)
		if err != nil { //coverage:ignore settings came from valid JSON.
			return nil, transformErrorWithCause("result.capabilities.settings", err)
		}
		capabilityObject[capability.Name] = encoded
	}
	meta, err := gatewayMeta(identity)
	if err != nil { //coverage:ignore validated identity is always JSON encodable.
		return nil, err
	}
	encodedCapabilities, err := json.Marshal(capabilityObject)
	if err != nil { //coverage:ignore capabilityObject contains valid JSON values.
		return nil, transformErrorWithCause("result.capabilities", err)
	}
	result := map[string]json.RawMessage{
		"resultType":        json.RawMessage(`"complete"`),
		"supportedVersions": json.RawMessage(`["` + ProtocolVersion + `"]`),
		"capabilities":      encodedCapabilities,
		"_meta":             meta,
		"ttlMs":             json.RawMessage(strconv.FormatInt(ttlMS, 10)),
		"cacheScope":        json.RawMessage(`"private"`),
	}
	encodedResult, err := json.Marshal(result)
	if err != nil { //coverage:ignore result contains valid JSON values.
		return nil, transformErrorWithCause("result", err)
	}
	idRaw := json.RawMessage(id.Value)
	if id.Kind == IDString {
		idRaw, err = json.Marshal(id.Value)
		if err != nil { //coverage:ignore strings are always JSON encodable.
			return nil, transformErrorWithCause("response.id", err)
		}
	} else if !json.Valid(idRaw) {
		return nil, transformError("response.id")
	} else if parsed, ok, parseErr := parseOptionalID(map[string]json.RawMessage{"id": idRaw}); parseErr != nil || !ok || parsed.Kind != IDNumber {
		return nil, transformError("response.id")
	}
	envelope := map[string]json.RawMessage{"jsonrpc": json.RawMessage(`"2.0"`), "id": idRaw, "result": encodedResult}
	body, err := json.Marshal(envelope)
	if err != nil { //coverage:ignore envelope contains valid JSON values.
		return nil, transformErrorWithCause("response", err)
	}
	return body, nil
}

func gatewayMeta(identity GatewayIdentity) (json.RawMessage, error) {
	serverInfo := map[string]string{"name": identity.Name, "version": identity.Version}
	if identity.Description != "" {
		serverInfo["description"] = identity.Description
	}
	if identity.WebsiteURL != "" {
		serverInfo["websiteUrl"] = identity.WebsiteURL
	}
	value := map[string]map[string]string{"io.modelcontextprotocol/serverInfo": serverInfo}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, transformErrorWithCause("result._meta", err)
	}
	return encoded, nil
}

func validateGatewayIdentity(identity GatewayIdentity) error {
	if identity.Name == "" || identity.Version == "" {
		return transformError("gateway.identity")
	}
	return nil
}

func validCapabilityName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		if character <= 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
