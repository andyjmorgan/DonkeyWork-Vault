package mcp

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func probeInput(status int, body string) ProbeInput {
	return ProbeInput{StatusCode: status, ContentType: "application/json; charset=utf-8", Body: []byte(body), RequestID: ID{Kind: IDString, Value: "probe-1"}}
}

func discoveryProbeBody(versions, capabilities, meta string) string {
	return `{"jsonrpc":"2.0","id":"probe-1","result":{"resultType":"complete","supportedVersions":` + versions + `,"capabilities":` + capabilities + meta + `,"ttlMs":1000,"cacheScope":"public"}}`
}

func TestClassifyProbeModern(t *testing.T) {
	body := discoveryProbeBody(`["2026-07-28","2025-11-25"]`, `{"tools":{"listChanged":true},"com.example/extension":{}}`, `,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"Datadog","version":"2.1","description":"ignored"}}`)
	result := ClassifyProbe(probeInput(200, body))
	if result.Class != ProbeModern202607 || result.Reason != ProbeReasonDiscoveryValid {
		t.Fatalf("unexpected classification: %+v", result)
	}
	if !reflect.DeepEqual(result.SupportedVersions, []string{"2026-07-28", "2025-11-25"}) {
		t.Fatalf("versions changed: %#v", result.SupportedVersions)
	}
	if result.Server != (ClientInfo{Name: "Datadog", Version: "2.1"}) {
		t.Fatalf("identity not preserved: %+v", result.Server)
	}
	if len(result.Capabilities) != 2 || result.Capabilities[0].Name != "com.example/extension" || result.Capabilities[1].Name != "tools" {
		t.Fatalf("capabilities not sorted: %+v", result.Capabilities)
	}
}

func TestClassifyProbeModernOptionalIdentity(t *testing.T) {
	result := ClassifyProbe(probeInput(200, discoveryProbeBody(`["2026-07-28"]`, `{}`, "")))
	if result.Class != ProbeModern202607 || result.Server != (ClientInfo{}) || len(result.Capabilities) != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	badMeta := discoveryProbeBody(`["2026-07-28"]`, `{}`, `,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":3}}`)
	result = ClassifyProbe(probeInput(200, badMeta))
	if result.Class != ProbeModern202607 || result.Server != (ClientInfo{}) {
		t.Fatalf("invalid optional identity affected classification: %+v", result)
	}
}

func TestClassifyProbeStatusFirst(t *testing.T) {
	tests := []struct {
		name   string
		status int
		class  ProbeClass
		reason ProbeReason
	}{
		{"unauthorized", 401, ProbeAuthRequired, ProbeReasonAuthorizationStatus},
		{"forbidden", 403, ProbeAuthRequired, ProbeReasonAuthorizationStatus},
		{"server error", 500, ProbeUnavailable, ProbeReasonServerFailure},
		{"gateway timeout", 504, ProbeUnavailable, ProbeReasonServerFailure},
		{"redirect", 302, ProbeUnknown, ProbeReasonRedirect},
		{"not found", 404, ProbeUnknown, ProbeReasonNotFound},
		{"teapot", 418, ProbeUnknown, ProbeReasonHTTPStatus},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ClassifyProbe(probeInput(test.status, `secret upstream payload`))
			if result.Class != test.class || result.Reason != test.reason {
				t.Fatalf("got %+v", result)
			}
		})
	}
}

func TestClassifyProbeLegacyErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		error  string
		reason ProbeReason
	}{
		{"method not found", 404, `{"code":-32601,"message":"Method not found"}`, ProbeReasonMethodNotFound},
		{"initialize clue", 400, `{"code":-32000,"message":"server must be initialized first"}`, ProbeReasonLegacySession},
		{"session clue", 400, `{"code":-32000,"message":"Mcp-Session-Id required"}`, ProbeReasonLegacySession},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":"probe-1","error":` + test.error + `}`
			result := ClassifyProbe(probeInput(test.status, body))
			if result.Class != ProbeLegacySessionLikely || result.Reason != test.reason {
				t.Fatalf("got %+v", result)
			}
		})
	}
}

func TestClassifyProbeUnsupportedVersions(t *testing.T) {
	legacy := `{"jsonrpc":"2.0","id":"probe-1","error":{"code":-32022,"message":"unsupported","data":{"supported":["2025-11-25","2025-06-18"],"requested":"2026-07-28"}}}`
	result := ClassifyProbe(probeInput(400, legacy))
	if result.Class != ProbeLegacySessionLikely || result.Reason != ProbeReasonLegacyVersion || len(result.SupportedVersions) != 2 {
		t.Fatalf("got %+v", result)
	}
	modern := strings.Replace(legacy, `["2025-11-25","2025-06-18"]`, `["2026-07-28"]`, 1)
	result = ClassifyProbe(probeInput(400, modern))
	if result.Class != ProbeUnknown || result.Reason != ProbeReasonModernError {
		t.Fatalf("got %+v", result)
	}
	missing := `{"jsonrpc":"2.0","id":"probe-1","error":{"code":-32022,"message":"unsupported"}}`
	result = ClassifyProbe(probeInput(400, missing))
	if result.Class != ProbeUnknown || result.Reason != ProbeReasonModernError || result.SupportedVersions != nil {
		t.Fatalf("got %+v", result)
	}
}

func TestClassifyProbeRecognizedModernErrors(t *testing.T) {
	for _, code := range []int{HeaderMismatchCode, -32602} {
		body := `{"jsonrpc":"2.0","id":"probe-1","error":{"code":` + strconv.Itoa(code) + `,"message":"do not leak me"}}`
		result := ClassifyProbe(probeInput(400, body))
		if result.Class != ProbeUnknown || result.Reason != ProbeReasonModernError {
			t.Fatalf("code %d: %+v", code, result)
		}
	}
}

func TestClassifyProbeMalformedSuccess(t *testing.T) {
	valid := discoveryProbeBody(`["2026-07-28"]`, `{"tools":{}}`, "")
	tests := []struct {
		name   string
		body   string
		reason ProbeReason
	}{
		{"empty", "", ProbeReasonMalformedSuccess},
		{"HTML", `<html>secret</html>`, ProbeReasonMalformedSuccess},
		{"wrong JSON-RPC", strings.Replace(valid, `"2.0"`, `"1.0"`, 1), ProbeReasonMalformedSuccess},
		{"wrong ID", strings.Replace(valid, `"probe-1"`, `"other"`, 1), ProbeReasonMismatchedID},
		{"number ID", strings.Replace(valid, `"probe-1"`, `1`, 1), ProbeReasonMismatchedID},
		{"missing ID", strings.Replace(valid, `"id":"probe-1",`, "", 1), ProbeReasonMismatchedID},
		{"method shape", strings.Replace(valid, `"result":`, `"method":"server/discover","result":`, 1), ProbeReasonMalformedSuccess},
		{"missing result", `{"jsonrpc":"2.0","id":"probe-1"}`, ProbeReasonMalformedSuccess},
		{"bad cache", strings.Replace(valid, `"ttlMs":1000`, `"ttlMs":-1`, 1), ProbeReasonMalformedSuccess},
		{"missing versions", strings.Replace(valid, `"supportedVersions":["2026-07-28"],`, "", 1), ProbeReasonMalformedSuccess},
		{"versions type", strings.Replace(valid, `["2026-07-28"]`, `true`, 1), ProbeReasonMalformedSuccess},
		{"empty version", strings.Replace(valid, `["2026-07-28"]`, `[""]`, 1), ProbeReasonMalformedSuccess},
		{"future version only", strings.Replace(valid, `["2026-07-28"]`, `["2099-01-01"]`, 1), ProbeReasonMalformedSuccess},
		{"missing capabilities", strings.Replace(valid, `"capabilities":{"tools":{}},`, "", 1), ProbeReasonMalformedSuccess},
		{"capabilities array", strings.Replace(valid, `"capabilities":{"tools":{}}`, `"capabilities":[]`, 1), ProbeReasonMalformedSuccess},
		{"bad capability name", strings.Replace(valid, `"tools"`, `"bad name"`, 1), ProbeReasonMalformedSuccess},
		{"bad capability settings", strings.Replace(valid, `{"tools":{}}`, `{"tools":true}`, 1), ProbeReasonMalformedSuccess},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ClassifyProbe(probeInput(200, test.body))
			if result.Class != ProbeIncompatible || result.Reason != test.reason {
				t.Fatalf("got %+v", result)
			}
		})
	}

	input := probeInput(200, valid)
	input.ContentType = "text/html"
	input.Body = []byte("not JSON")
	result := ClassifyProbe(input)
	if result.Class != ProbeIncompatible || result.Reason != ProbeReasonUnexpectedContent {
		t.Fatalf("got %+v", result)
	}
}

func TestClassifyProbeErrorEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		reason ProbeReason
	}{
		{"wrong error ID", `{"jsonrpc":"2.0","id":"other","error":{"code":-32601,"message":"x"}}`, ProbeReasonMismatchedID},
		{"idless method missing", `{"jsonrpc":"2.0","error":{"code":-32601,"message":"x"}}`, ProbeReasonMethodNotFound},
		{"invalid error object", `{"jsonrpc":"2.0","id":"probe-1","error":true}`, ProbeReasonHTTPStatus},
		{"invalid code", `{"jsonrpc":"2.0","id":"probe-1","error":{"code":"x","message":"x"}}`, ProbeReasonHTTPStatus},
		{"unrecognized code", `{"jsonrpc":"2.0","id":"probe-1","error":{"code":-32099,"message":"other"}}`, ProbeReasonHTTPStatus},
		{"invalid JSONRPC", `{"jsonrpc":"1.0","id":"probe-1","error":{"code":-32601,"message":"x"}}`, ProbeReasonHTTPStatus},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ClassifyProbe(probeInput(400, test.body))
			if result.Reason != test.reason {
				t.Fatalf("got %+v", result)
			}
		})
	}
}

func TestProbeHelpers(t *testing.T) {
	if !isJSONContentType("application/problem+json") || !isJSONContentType("Application/JSON") || isJSONContentType("bogus;") || isJSONContentType("text/plain") {
		t.Fatal("content type classification mismatch")
	}
	if !probeIDsEqual(ID{Kind: IDNumber, Value: "1"}, ID{Kind: IDNumber, Value: "1"}) || probeIDsEqual(ID{Kind: IDString, Value: "1"}, ID{Kind: IDNumber, Value: "1"}) {
		t.Fatal("ID comparison mismatch")
	}
	if !containsString([]string{"a", "b"}, "b") || containsString([]string{"a"}, "b") {
		t.Fatal("contains mismatch")
	}
	if !allLegacyVersions([]string{"2025-11-25"}) || allLegacyVersions(nil) || allLegacyVersions([]string{"not-a-date"}) || allLegacyVersions([]string{ProtocolVersion}) {
		t.Fatal("legacy version mismatch")
	}
	if versions := probeSupportedVersions(map[string]json.RawMessage{}); versions != nil {
		t.Fatalf("unexpected versions: %#v", versions)
	}
}

func FuzzClassifyProbe(f *testing.F) {
	f.Add(200, "application/json", discoveryProbeBody(`["2026-07-28"]`, `{}`, ""))
	f.Add(400, "text/plain", "")
	f.Fuzz(func(_ *testing.T, status int, contentType, body string) {
		_ = ClassifyProbe(ProbeInput{StatusCode: status, ContentType: contentType, Body: []byte(body), RequestID: ID{Kind: IDString, Value: "probe-1"}})
	})
}
