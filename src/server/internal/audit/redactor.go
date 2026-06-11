package audit

import "strings"

// Redacted is the placeholder stored in place of any non-allowlisted header value.
const Redacted = "***"

// allowlist: stored verbatim. Known-safe, non-secret headers only.
var allowlist = map[string]bool{
	"user-agent": true, "content-type": true, "accept": true, "x-request-id": true,
	"traceparent": true, "x-forwarded-for": true, "x-real-ip": true,
	"x-forwarded-proto": true, "host": true,
}

// denyExact: always redacted, even if otherwise innocuous-looking.
var denyExact = map[string]bool{
	"authorization": true, "x-api-key": true, "x-internal-token": true,
	"cookie": true, "set-cookie": true, "proxy-authorization": true,
}

// RedactHeader returns the verbatim value for an allowlisted header, otherwise Redacted. Deny
// patterns (*token* / *secret* / *password* / *-key) and the explicit deny list always win.
func RedactHeader(name, value string) string {
	if name == "" {
		return Redacted
	}
	if IsDenied(name) {
		return Redacted
	}
	if allowlist[strings.ToLower(name)] {
		return value
	}
	return Redacted
}

// RedactHeaders projects a header set into the redacted map stored on an event. Keys are
// lower-cased; the first occurrence of a duplicate key wins.
func RedactHeaders(headers map[string][]string) map[string]string {
	out := make(map[string]string, len(headers))
	for name, values := range headers {
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, exists := out[key]; exists {
			continue
		}
		v := ""
		if len(values) > 0 {
			v = values[0]
		}
		out[key] = RedactHeader(name, v)
	}
	return out
}

// IsDenied reports whether a header name is denied by exact match or a secret-bearing pattern.
func IsDenied(name string) bool {
	lower := strings.ToLower(name)
	if denyExact[lower] {
		return true
	}
	return strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "password") ||
		strings.HasSuffix(lower, "-key")
}
