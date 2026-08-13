package mcp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func validHeaders(method, name string) http.Header {
	headers := http.Header{
		"Mcp-Protocol-Version": {ProtocolVersion},
		"Mcp-Method":           {method},
	}
	if name != "" {
		headers["Mcp-Name"] = []string{name}
	}
	return headers
}

func requestBody(id, method, params string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"` + method + `","params":{` + params + `,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"harness","version":"1.2"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
}

func TestInspectClientRequest(t *testing.T) {
	body := requestBody(`"run-1"`, "tools/call", `"name":"search","arguments":{"region":"us-west1","nested":{"tenant":42},"enabled":true},"requestState":"opaque-secret"`)
	headers := validHeaders("tools/call", "search")
	headers.Set("Mcp-Param-Region", "us-west1")
	headers.Set("Mcp-Param-Tenant", "42")
	headers.Set("Mcp-Param-Enabled", "true")
	key := []byte("audit-key")
	message, err := InspectClient([]byte(body), headers, Options{
		RequestStateHMACKey: key,
		ParamHeaders: []ParamHeader{
			{Name: "Region", ArgumentPath: []string{"region"}, Required: true},
			{Name: "Tenant", ArgumentPath: []string{"nested", "tenant"}},
			{Name: "Enabled", ArgumentPath: []string{"enabled"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if message.Kind != KindRequest || message.ID != (ID{Kind: IDString, Value: "run-1"}) {
		t.Fatalf("unexpected request identity: %+v", message)
	}
	if message.ProtocolVersion != ProtocolVersion || message.Client != (ClientInfo{Name: "harness", Version: "1.2"}) {
		t.Fatalf("unexpected metadata: %+v", message)
	}
	if message.Audit.Method != "tools/call" || message.Audit.ToolName != "search" {
		t.Fatalf("unexpected audit fields: %+v", message.Audit)
	}
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write([]byte("opaque-secret"))
	wantDigest := "hmac-sha256:" + hex.EncodeToString(digest.Sum(nil))
	if message.Audit.RequestStateDigest != wantDigest || strings.Contains(message.Audit.RequestStateDigest, "opaque") {
		t.Fatalf("unsafe or wrong digest: %q", message.Audit.RequestStateDigest)
	}
}

func TestInspectClientRequestMetadataAndNames(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		params     string
		headerName string
		field      string
		want       string
	}{
		{"resource", "resources/read", `"uri":"file:///tmp/a"`, "file:///tmp/a", "resource", "file:///tmp/a"},
		{"prompt", "prompts/get", `"name":"review"`, "review", "prompt", "review"},
		{"other", "tools/list", `"cursor":"x"`, "", "", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message, err := InspectClient([]byte(requestBody("7", test.method, test.params)), validHeaders(test.method, test.headerName), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if message.ID != (ID{Kind: IDNumber, Value: "7"}) {
				t.Fatalf("wrong ID: %+v", message.ID)
			}
			switch test.field {
			case "resource":
				if message.Audit.ResourceURI != test.want {
					t.Fatalf("got %q", message.Audit.ResourceURI)
				}
			case "prompt":
				if message.Audit.PromptName != test.want {
					t.Fatalf("got %q", message.Audit.PromptName)
				}
			}
		})
	}
}

func TestInspectClientReportsCursorPresence(t *testing.T) {
	body := requestBody("7", "tools/list", `"cursor":"next"`)
	message, err := InspectClient([]byte(body), validHeaders("tools/list", ""), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !message.HasCursor {
		t.Fatal("expected cursor presence")
	}
}

func TestInspectClientNotification(t *testing.T) {
	body := `{"jsonrpc":"2.0","method":"example/notice","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	message, err := InspectClient([]byte(body), validHeaders("example/notice", ""), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if message.Kind != KindNotification || message.ID.Kind != IDNone || message.Audit.Method != "example/notice" {
		t.Fatalf("unexpected notification: %+v", message)
	}
}

func TestInspectClientRejectsInvalidMessages(t *testing.T) {
	valid := requestBody("1", "tools/list", `"cursor":"x"`)
	tests := []struct {
		name string
		body string
		kind ErrorKind
	}{
		{"empty", "", ErrorInvalidJSON},
		{"array", "[]", ErrorInvalidMessage},
		{"trailing", valid + `{}`, ErrorInvalidJSON},
		{"trailing garbage", valid + `x`, ErrorInvalidJSON},
		{"bad version", strings.Replace(valid, `"2.0"`, `"1.0"`, 1), ErrorInvalidMessage},
		{"missing method", strings.Replace(valid, `"method":"tools/list",`, "", 1), ErrorInvalidMessage},
		{"empty method", strings.Replace(valid, `"tools/list"`, `""`, 1), ErrorInvalidMessage},
		{"null id", strings.Replace(valid, `"id":1`, `"id":null`, 1), ErrorInvalidMessage},
		{"boolean id", strings.Replace(valid, `"id":1`, `"id":true`, 1), ErrorInvalidMessage},
		{"object id", strings.Replace(valid, `"id":1`, `"id":{}`, 1), ErrorInvalidMessage},
		{"result from client", strings.Replace(valid, `"method":"tools/list"`, `"method":"tools/list","result":{}`, 1), ErrorInvalidMessage},
		{"error from client", strings.Replace(valid, `"method":"tools/list"`, `"method":"tools/list","error":{}`, 1), ErrorInvalidMessage},
		{"params array", strings.Replace(valid, `"params":{`, `"params":[`, 1), ErrorInvalidJSON},
		{"missing meta", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, ErrorInvalidMessage},
		{"missing capabilities", strings.Replace(valid, `,"io.modelcontextprotocol/clientCapabilities":{}`, "", 1), ErrorInvalidMessage},
		{"capabilities array", strings.Replace(valid, `"io.modelcontextprotocol/clientCapabilities":{}`, `"io.modelcontextprotocol/clientCapabilities":[]`, 1), ErrorInvalidMessage},
		{"client info bad", strings.Replace(valid, `{"name":"harness","version":"1.2"}`, `{"name":"harness"}`, 1), ErrorInvalidMessage},
		{"unsupported", strings.Replace(valid, ProtocolVersion, "2099-01-01", 1), ErrorUnsupportedVersion},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := InspectClient([]byte(test.body), validHeaders("tools/list", ""), Options{})
			if !IsErrorKind(err, test.kind) {
				t.Fatalf("got %v, want %s", err, test.kind)
			}
			if err != nil && strings.Contains(err.Error(), "harness") {
				t.Fatalf("error leaked input: %v", err)
			}
		})
	}
}

func TestHeaderValidation(t *testing.T) {
	body := requestBody("1", "tools/call", `"name":"search","arguments":{"value":"Hello, 世界"}`)
	encoded := encodedPrefix + base64.StdEncoding.EncodeToString([]byte("Hello, 世界")) + encodedSuffix
	tests := []struct {
		name    string
		mutate  func(http.Header)
		options Options
		wantErr bool
	}{
		{name: "valid encoded name", mutate: func(h http.Header) {
			h.Set("Mcp-Name", encodedPrefix+base64.StdEncoding.EncodeToString([]byte("search"))+encodedSuffix)
		}},
		{name: "missing protocol", mutate: func(h http.Header) { h.Del("Mcp-Protocol-Version") }, wantErr: true},
		{name: "protocol mismatch", mutate: func(h http.Header) { h.Set("Mcp-Protocol-Version", "old") }, wantErr: true},
		{name: "missing method", mutate: func(h http.Header) { h.Del("Mcp-Method") }, wantErr: true},
		{name: "method mismatch", mutate: func(h http.Header) { h.Set("Mcp-Method", "TOOLS/CALL") }, wantErr: true},
		{name: "missing name", mutate: func(h http.Header) { h.Del("Mcp-Name") }, wantErr: true},
		{name: "name mismatch", mutate: func(h http.Header) { h.Set("Mcp-Name", "other") }, wantErr: true},
		{name: "missing body name", mutate: func(http.Header) {}, wantErr: true},
		{name: "invalid encoded", mutate: func(h http.Header) { h.Set("Mcp-Name", "=?base64?!!!?=") }, wantErr: true},
		{name: "invalid UTF8 encoded", mutate: func(h http.Header) { h.Set("Mcp-Name", "=?base64?/w==?=") }, wantErr: true},
		{name: "incomplete sentinel literal mismatch", mutate: func(h http.Header) { h.Set("Mcp-Name", "=?base64?c2VhcmNo") }, wantErr: true},
		{name: "uppercase sentinel literal mismatch", mutate: func(h http.Header) { h.Set("Mcp-Name", "=?BASE64?c2VhcmNo?=") }, wantErr: true},
		{name: "duplicate name", mutate: func(h http.Header) { h["Mcp-Name"] = []string{"search", "search"} }, wantErr: true},
		{name: "valid parameter", mutate: func(h http.Header) { h.Set("Mcp-Param-Value", encoded) }, options: Options{ParamHeaders: []ParamHeader{{Name: "Value", ArgumentPath: []string{"value"}, Required: true}}}},
		{name: "missing required parameter", mutate: func(http.Header) {}, options: Options{ParamHeaders: []ParamHeader{{Name: "Value", ArgumentPath: []string{"value"}, Required: true}}}, wantErr: true},
		{name: "optional header absent body present", mutate: func(http.Header) {}, options: Options{ParamHeaders: []ParamHeader{{Name: "Value", ArgumentPath: []string{"value"}}}}, wantErr: true},
		{name: "invalid annotation", mutate: func(http.Header) {}, options: Options{ParamHeaders: []ParamHeader{{Name: "Bad Name", ArgumentPath: []string{"value"}}}}, wantErr: true},
		{name: "empty path", mutate: func(http.Header) {}, options: Options{ParamHeaders: []ParamHeader{{Name: "Value"}}}, wantErr: true},
		{name: "duplicate annotations", mutate: func(http.Header) {}, options: Options{ParamHeaders: []ParamHeader{{Name: "Value", ArgumentPath: []string{"value"}}, {Name: "value", ArgumentPath: []string{"value"}}}}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := validHeaders("tools/call", "search")
			testBody := body
			if test.name == "missing body name" {
				testBody = requestBody("1", "tools/call", `"arguments":{}`)
			}
			test.mutate(headers)
			_, err := InspectClient([]byte(testBody), headers, test.options)
			if (err != nil) != test.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, test.wantErr)
			}
			if err != nil && !IsErrorKind(err, ErrorHeaderMismatch) {
				t.Fatalf("unexpected error kind: %v", err)
			}
		})
	}
}

func TestParameterHeaderEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		arguments string
		binding   ParamHeader
		header    string
		setHeader bool
	}{
		{name: "optional both absent", arguments: `{}`, binding: ParamHeader{Name: "Value", ArgumentPath: []string{"value"}}},
		{name: "required body absent", arguments: `{}`, binding: ParamHeader{Name: "Value", ArgumentPath: []string{"value"}, Required: true}},
		{name: "header without body", arguments: `{}`, binding: ParamHeader{Name: "Value", ArgumentPath: []string{"value"}}, header: "x", setHeader: true},
		{name: "nested absent", arguments: `{"nested":{}}`, binding: ParamHeader{Name: "Value", ArgumentPath: []string{"nested", "value"}}},
		{name: "nested not object", arguments: `{"nested":"x"}`, binding: ParamHeader{Name: "Value", ArgumentPath: []string{"nested", "value"}}, header: "x", setHeader: true},
		{name: "invalid literal header", arguments: `{"value":"x"}`, binding: ParamHeader{Name: "Value", ArgumentPath: []string{"value"}}, header: "x\x7f", setHeader: true},
		{name: "empty annotation", arguments: `{}`, binding: ParamHeader{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := requestBody("1", "tools/call", `"name":"x","arguments":`+test.arguments)
			headers := validHeaders("tools/call", "x")
			if test.setHeader {
				headers["Mcp-Param-Value"] = []string{test.header}
			}
			_, err := InspectClient([]byte(body), headers, Options{ParamHeaders: []ParamHeader{test.binding}})
			wantErr := test.name != "optional both absent" && test.name != "nested absent"
			if (err != nil) != wantErr {
				t.Fatalf("err=%v wantErr=%v", err, wantErr)
			}
		})
	}
}

func TestParameterHeaderValueTypes(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		header  string
		wantErr bool
	}{
		{"string", `"a b"`, "a b", false},
		{"boolean", "false", "false", false},
		{"integer", "-7", "-7", false},
		{"decimal", "3.14", "3.14", true},
		{"exponent integer", "1e2", "100", false},
		{"large", "9007199254740992", "9007199254740992", true},
		{"null", "null", "null", true},
		{"object", `{}`, "x", true},
		{"array", `[]`, "x", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := requestBody("1", "tools/call", `"name":"x","arguments":{"value":`+test.value+`}`)
			headers := validHeaders("tools/call", "x")
			headers.Set("Mcp-Param-Value", test.header)
			_, err := InspectClient([]byte(body), headers, Options{ParamHeaders: []ParamHeader{{Name: "Value", ArgumentPath: []string{"value"}}}})
			if (err != nil) != test.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestInspectServerMessages(t *testing.T) {
	tests := []struct {
		name string
		body string
		kind Kind
	}{
		{"notification", `{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":"sub-1"}}}`, KindNotification},
		{"result", `{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required","inputRequests":{"z":{"method":"sampling/createMessage","params":{}},"a":{"method":"elicitation/create","params":{}}},"requestState":"secret"}}`, KindResult},
		{"error", `{"jsonrpc":"2.0","id":"x","error":{"code":-32601,"message":"missing"}}`, KindError},
		{"idless error", `{"jsonrpc":"2.0","error":{"code":-32700,"message":"parse"}}`, KindError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message, err := InspectServer([]byte(test.body), nil)
			if err != nil {
				t.Fatal(err)
			}
			if message.Kind != test.kind {
				t.Fatalf("got %+v", message)
			}
			switch test.kind {
			case KindNotification:
				if message.Audit.SubscriptionID != (ID{Kind: IDString, Value: "sub-1"}) {
					t.Fatalf("bad subscription: %+v", message)
				}
			case KindResult:
				if message.Audit.ResultType != "input_required" || strings.Contains(message.Audit.RequestStateDigest, "secret") {
					t.Fatalf("bad result: %+v", message)
				}
				if strings.Join(message.Audit.InputRequestMethods, ",") != "elicitation/create,sampling/createMessage" {
					t.Fatalf("unstable methods: %#v", message.Audit.InputRequestMethods)
				}
			case KindError:
				if message.ErrorCode == 0 {
					t.Fatal("missing error code")
				}
			}
		})
	}
}

func TestInspectServerRejectsInvalidMessages(t *testing.T) {
	tests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"server/request","params":{}}`,
		`{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}`,
		`{"jsonrpc":"2.0","id":1,"result":null}`,
		`{"jsonrpc":"2.0","error":null}`,
		`{"jsonrpc":"2.0","error":{"code":1.2,"message":"x"}}`,
		`{"jsonrpc":"2.0","error":{"code":1,"message":3}}`,
		`{"jsonrpc":"2.0","method":""}`,
		`{"jsonrpc":"2.0","method":"notifications/x","params":[]}`,
		`{"jsonrpc":"2.0","id":true,"result":{}}`,
	}
	for _, body := range tests {
		if _, err := InspectServer([]byte(body), nil); !IsErrorKind(err, ErrorInvalidMessage) {
			t.Errorf("body %s: got %v", body, err)
		}
	}
}

func TestValidationError(t *testing.T) {
	err := invalidMessage("field", errMissingHeader)
	if err.Error() != "MCP invalid_message: field" || !IsErrorKind(err, ErrorInvalidMessage) {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "field") {
		t.Fatal("field absent")
	}
	var validation *ValidationError
	if !strings.Contains((&ValidationError{Kind: ErrorInvalidJSON}).Error(), "invalid_json") || !strings.Contains(err.Error(), "field") {
		t.Fatal("bad error formatting")
	}
	if !errors.Is(err, errMissingHeader) {
		t.Fatal("validation error did not unwrap")
	}
	_ = validation
}
