package mcp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	encodedPrefix = "=?base64?"
	encodedSuffix = "?="
)

// ParamHeader describes one x-mcp-header annotation previously obtained from a tool schema.
type ParamHeader struct {
	// Name is the annotation value, without the Mcp-Param- prefix.
	Name string
	// ArgumentPath is the chain of properties below params.arguments.
	ArgumentPath []string
	// Required rejects a missing argument or header. Optional annotations require both or neither.
	Required bool
}

func validateHeaders(headers http.Header, method, version string, params map[string]json.RawMessage, bindings []ParamHeader) error {
	protocolHeader, err := singleHeader(headers, "MCP-Protocol-Version")
	if err != nil || protocolHeader != version {
		return headerMismatch("MCP-Protocol-Version", err)
	}
	methodHeader, err := singleHeader(headers, "Mcp-Method")
	if err != nil || methodHeader != method {
		return headerMismatch("Mcp-Method", err)
	}

	nameField := ""
	switch method {
	case "tools/call", "prompts/get":
		nameField = "name"
	case "resources/read":
		nameField = "uri"
	}
	if nameField != "" {
		bodyName, ok := optionalString(params, nameField)
		if !ok {
			return headerMismatch("Mcp-Name", errors.New("missing body field"))
		}
		headerName, err := decodedHeader(headers, "Mcp-Name")
		if err != nil || headerName != bodyName {
			return headerMismatch("Mcp-Name", err)
		}
	}
	if method != "tools/call" || len(bindings) == 0 {
		return nil
	}
	arguments, _, err := optionalObject(params, "arguments")
	if err != nil {
		return headerMismatch("params.arguments", err)
	}
	seen := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if !validToken(binding.Name) || len(binding.ArgumentPath) == 0 {
			return headerMismatch("Mcp-Param annotation", nil)
		}
		folded := strings.ToLower(binding.Name)
		if _, duplicate := seen[folded]; duplicate {
			return headerMismatch("Mcp-Param annotation", nil)
		}
		seen[folded] = struct{}{}
		bodyValue, present, valueErr := argumentHeaderValue(arguments, binding.ArgumentPath)
		if valueErr != nil {
			return headerMismatch("Mcp-Param-"+binding.Name, valueErr)
		}
		headerValue, headerErr := decodedHeader(headers, "Mcp-Param-"+binding.Name)
		headerPresent := headerErr == nil
		if headerErr != nil && !errors.Is(headerErr, errMissingHeader) {
			return headerMismatch("Mcp-Param-"+binding.Name, headerErr)
		}
		if binding.Required && (!present || !headerPresent) {
			return headerMismatch("Mcp-Param-"+binding.Name, errMissingHeader)
		}
		if present != headerPresent || present && headerValue != bodyValue {
			return headerMismatch("Mcp-Param-"+binding.Name, nil)
		}
	}
	return nil
}

var errMissingHeader = errors.New("missing header")

func singleHeader(headers http.Header, name string) (string, error) {
	values := make([]string, 0, 1)
	for key, candidate := range headers {
		if strings.EqualFold(key, name) {
			values = append(values, candidate...)
		}
	}
	if len(values) == 0 {
		return "", errMissingHeader
	}
	if len(values) != 1 {
		return "", errors.New("duplicate header")
	}
	return strings.Trim(values[0], " \t"), nil
}

func decodedHeader(headers http.Header, name string) (string, error) {
	value, err := singleHeader(headers, name)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(value, encodedPrefix) && strings.HasSuffix(value, encodedSuffix) {
		encoded := value[len(encodedPrefix) : len(value)-len(encodedSuffix)]
		decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || !utf8.Valid(decoded) {
			return "", errors.New("invalid encoded header")
		}
		return string(decoded), nil
	}
	for _, char := range []byte(value) {
		if char < 0x20 || char > 0x7e {
			return "", errors.New("invalid literal header")
		}
	}
	return value, nil
}

func argumentHeaderValue(arguments map[string]json.RawMessage, path []string) (string, bool, error) {
	current := arguments
	for index, segment := range path {
		raw, ok := current[segment]
		if !ok {
			return "", false, nil
		}
		if index == len(path)-1 {
			value, err := primitiveHeaderValue(raw)
			return value, true, err
		}
		next, err := rawObject(raw, "argument")
		if err != nil {
			return "", true, err
		}
		current = next
	}
	return "", false, nil
}

func primitiveHeaderValue(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("empty value")
	}
	switch raw[0] {
	case '"':
		return rawString(raw)
	case 't', 'f':
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", err
		}
		return strconv.FormatBool(value), nil
	case 'n', '{', '[':
		return "", errors.New("non-primitive value")
	default:
		var rational big.Rat
		if _, ok := rational.SetString(string(raw)); !ok || !rational.IsInt() {
			return "", errors.New("non-integer number")
		}
		integer := rational.Num()
		limit := big.NewInt(9007199254740991)
		if new(big.Int).Abs(new(big.Int).Set(integer)).Cmp(limit) > 0 {
			return "", errors.New("integer outside safe range")
		}
		return integer.String(), nil
	}
}

func validToken(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range []byte(value) {
		isAlphaNumeric := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
		if !isAlphaNumeric && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(char)) {
			return false
		}
	}
	return true
}

func headerMismatch(field string, err error) error {
	return &ValidationError{Kind: ErrorHeaderMismatch, Field: field, err: err}
}
