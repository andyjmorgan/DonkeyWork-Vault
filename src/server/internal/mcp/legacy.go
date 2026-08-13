package mcp

import (
	"encoding/json"
	"strings"
)

// UpgradeLegacyResponse converts a session-era response into the July 2026 result envelope
// exposed by the stateless gateway. Errors and notifications are returned unchanged.
func UpgradeLegacyResponse(body []byte, method string) ([]byte, error) {
	envelope, err := decodeObject(body)
	if err != nil {
		return nil, err
	}
	if err := validateBase(envelope); err != nil {
		return nil, err
	}
	if _, isError := envelope["error"]; isError {
		return append([]byte(nil), body...), nil
	}
	if _, isNotification := envelope["method"]; isNotification {
		return append([]byte(nil), body...), nil
	}
	result, ok, err := optionalObject(envelope, "result")
	if err != nil || !ok {
		return nil, invalidMessage("result", err)
	}
	if _, exists := result["resultType"]; !exists {
		result["resultType"] = json.RawMessage(`"complete"`)
	}
	if legacyCacheableMethod(method) {
		if _, exists := result["ttlMs"]; !exists {
			result["ttlMs"] = json.RawMessage(`0`)
		}
		// Legacy results were produced inside a caller-specific authenticated session. They must
		// never become shared cache entries when exposed through the stateless gateway.
		result["cacheScope"] = json.RawMessage(`"private"`)
	}
	return encodeResultEnvelope(envelope, result)
}

func legacyCacheableMethod(method string) bool {
	return strings.HasSuffix(method, "/list") || method == "resources/templates/list"
}
