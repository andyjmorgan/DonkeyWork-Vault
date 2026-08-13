package mcp

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func toolsResponse(tools, extras string) string {
	return `{"jsonrpc":"2.0","id":"list-1","result":{"resultType":"complete","tools":` + tools + `,"nextCursor":"next","ttlMs":300000,"cacheScope":"public","_meta":{"upstream":"kept"}` + extras + `}}`
}

func validTool(name, schema string) string {
	return `{"name":"` + name + `","title":"Title","inputSchema":` + schema + `,"_meta":{"provider":"kept"}}`
}

func TestTransformToolsList(t *testing.T) {
	schema := `{"type":"object","required":["region","nested","enabled"],"properties":{` +
		`"region":{"type":"string","x-mcp-header":"Region"},` +
		`"nested":{"type":"object","required":["tenant"],"properties":{"tenant":{"type":"integer","x-mcp-header":"Tenant-ID"}}},` +
		`"enabled":{"type":"boolean","x-mcp-header":"Enabled"},` +
		`"optional":{"type":"string","x-mcp-header":"Optional"}}}`
	body := toolsResponse(`[`+validTool("search", schema)+`,`+validTool("other", `{"type":"object"}`)+`]`, `,"vendor":"preserved"`)
	transformed, err := TransformToolsList([]byte(body), func(name string) bool { return name == "search" })
	if err != nil {
		t.Fatal(err)
	}
	if !transformed.Filtered || len(transformed.Tools) != 1 || transformed.Tools[0].Name != "search" {
		t.Fatalf("unexpected transformation: %+v", transformed)
	}
	if !transformed.NextCursorPresent {
		t.Fatal("next cursor presence not reported")
	}
	wantHeaders := []ParamHeaderDefinition{
		{Name: "Enabled", ArgumentPath: []string{"enabled"}, Required: true, Type: PrimitiveBoolean},
		{Name: "Tenant-ID", ArgumentPath: []string{"nested", "tenant"}, Required: true, Type: PrimitiveInteger},
		{Name: "Optional", ArgumentPath: []string{"optional"}, Type: PrimitiveString},
		{Name: "Region", ArgumentPath: []string{"region"}, Required: true, Type: PrimitiveString},
	}
	if !reflect.DeepEqual(transformed.Tools[0].ParamHeaders, wantHeaders) {
		t.Fatalf("headers mismatch:\n got %#v\nwant %#v", transformed.Tools[0].ParamHeaders, wantHeaders)
	}
	if got := transformed.Tools[0].HeaderBindings(); !reflect.DeepEqual(got, []ParamHeader{
		{Name: "Enabled", ArgumentPath: []string{"enabled"}, Required: true},
		{Name: "Tenant-ID", ArgumentPath: []string{"nested", "tenant"}, Required: true},
		{Name: "Optional", ArgumentPath: []string{"optional"}},
		{Name: "Region", ArgumentPath: []string{"region"}, Required: true},
	}) {
		t.Fatalf("bindings mismatch: %#v", got)
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(transformed.Body, &envelope); err != nil {
		t.Fatal(err)
	}
	if string(envelope["id"]) != `"list-1"` {
		t.Fatalf("ID not preserved: %s", envelope["id"])
	}
	result, _, err := optionalObject(envelope, "result")
	if err != nil {
		t.Fatal(err)
	}
	if string(result["cacheScope"]) != `"private"` || string(result["nextCursor"]) != `"next"` || string(result["ttlMs"]) != "300000" {
		t.Fatalf("result fields not preserved/private: %s", transformed.Body)
	}
	if _, ok := result["vendor"]; !ok {
		t.Fatal("vendor field lost")
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(result["tools"], &tools); err != nil || len(tools) != 1 || !strings.Contains(string(tools[0]), `"provider":"kept"`) {
		t.Fatalf("raw tool metadata lost: %s (%v)", result["tools"], err)
	}
}

func TestTransformToolsListNoFilteringPreservesScopeAndOrder(t *testing.T) {
	body := toolsResponse(`[`+validTool("z", `{"type":"object"}`)+`,`+validTool("a", `{"type":"object"}`)+`]`, "")
	transformed, err := TransformToolsList([]byte(body), nil)
	if err != nil {
		t.Fatal(err)
	}
	if transformed.Filtered || len(transformed.Excluded) != 0 || transformed.Tools[0].Name != "z" || transformed.Tools[1].Name != "a" {
		t.Fatalf("order/filter changed: %+v", transformed)
	}
	if !transformed.NextCursorPresent {
		t.Fatal("next cursor presence not reported")
	}
	if !strings.Contains(string(transformed.Body), `"cacheScope":"public"`) {
		t.Fatalf("public scope changed: %s", transformed.Body)
	}
}

func TestTransformToolsListExcludesInvalidTools(t *testing.T) {
	longName := strings.Repeat("x", 129)
	tools := []string{
		`null`,
		validTool("", `{"type":"object"}`),
		validTool(longName, `{"type":"object"}`),
		`{"name":"missing"}`,
		validTool("schema-array", `[]`),
		validTool("wrong-root", `{"type":"string"}`),
		validTool("bad-name", `{"type":"object","properties":{"x":{"type":"string","x-mcp-header":"Bad Name"}}}`),
		validTool("empty-header", `{"type":"object","properties":{"x":{"type":"string","x-mcp-header":""}}}`),
		validTool("bad-header-type", `{"type":"object","properties":{"x":{"type":"number","x-mcp-header":"X"}}}`),
		validTool("missing-header-type", `{"type":"object","properties":{"x":{"x-mcp-header":"X"}}}`),
		validTool("duplicate-header", `{"type":"object","properties":{"x":{"type":"string","x-mcp-header":"X"},"y":{"type":"string","x-mcp-header":"x"}}}`),
		validTool("root-header", `{"type":"object","x-mcp-header":"Root"}`),
		validTool("unreachable-items", `{"type":"object","properties":{"list":{"type":"array","items":{"type":"string","x-mcp-header":"Item"}}}}`),
		validTool("unreachable-composition", `{"type":"object","oneOf":[{"properties":{"x":{"type":"string","x-mcp-header":"X"}}}]}`),
		validTool("bad-property", `{"type":"object","properties":{"x":true}}`),
		validTool("bad-required", `{"type":"object","required":true}`),
		validTool("duplicate", `{"type":"object"}`),
		validTool("duplicate", `{"type":"object"}`),
		validTool("good", `{"type":"object","properties":{"value":{"type":"string","x-mcp-header":"Value"}}}`),
	}
	transformed, err := TransformToolsList([]byte(toolsResponse("["+strings.Join(tools, ",")+"]", "")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(transformed.Tools) != 2 || transformed.Tools[0].Name != "duplicate" || transformed.Tools[1].Name != "good" {
		t.Fatalf("unexpected accepted tools: %+v", transformed.Tools)
	}
	if len(transformed.Excluded) != len(tools)-2 || transformed.Excluded[len(transformed.Excluded)-1].Reason != "duplicate_name" {
		t.Fatalf("unexpected exclusions: %+v", transformed.Excluded)
	}
	for _, excluded := range transformed.Excluded {
		if strings.Contains(excluded.Reason, "Bad Name") {
			t.Fatalf("reason leaked response value: %+v", excluded)
		}
	}
}

func TestTransformToolsListRejectsInvalidEnvelope(t *testing.T) {
	valid := toolsResponse(`[]`, "")
	tests := []struct {
		name string
		body string
	}{
		{"invalid JSON", "{"},
		{"array", "[]"},
		{"wrong jsonrpc", strings.Replace(valid, `"2.0"`, `"1.0"`, 1)},
		{"missing id", strings.Replace(valid, `"id":"list-1",`, "", 1)},
		{"invalid id", strings.Replace(valid, `"id":"list-1"`, `"id":null`, 1)},
		{"error response", `{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"secret"}}`},
		{"request shape", `{"jsonrpc":"2.0","id":1,"method":"tools/list","result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"public"}}`},
		{"missing result", `{"jsonrpc":"2.0","id":1}`},
		{"result array", `{"jsonrpc":"2.0","id":1,"result":[]}`},
		{"missing result type", strings.Replace(valid, `"resultType":"complete",`, "", 1)},
		{"wrong result type", strings.Replace(valid, `"complete"`, `"input_required"`, 1)},
		{"missing ttl", strings.Replace(valid, `"ttlMs":300000,`, "", 1)},
		{"negative ttl", strings.Replace(valid, "300000", "-1", 1)},
		{"string ttl", strings.Replace(valid, "300000", `"300000"`, 1)},
		{"missing scope", strings.Replace(valid, `"cacheScope":"public",`, "", 1)},
		{"bad scope", strings.Replace(valid, `"public"`, `"shared"`, 1)},
		{"missing tools", strings.Replace(valid, `"tools":[],`, "", 1)},
		{"tools object", strings.Replace(valid, `"tools":[]`, `"tools":{}`, 1)},
		{"tools invalid", strings.Replace(valid, `"tools":[]`, `"tools":[`, 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := TransformToolsList([]byte(test.body), nil)
			var target *TransformError
			if !errors.As(err, &target) {
				t.Fatalf("got %v", err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("error leaked content: %v", err)
			}
		})
	}
}

func TestTransformErrorAndHelperCoverage(t *testing.T) {
	cause := errors.New("cause")
	err := transformErrorWithCause("field", cause)
	if err.Error() != "invalid MCP transformation input: field" || !errors.Is(err, cause) || errorField(err) != "field" {
		t.Fatalf("unexpected error: %v", err)
	}
	if errorField(cause) != "tool" {
		t.Fatal("unexpected fallback")
	}
	if _, err := schemaRequiredNames(map[string]json.RawMessage{"required": json.RawMessage(`true`)}); err == nil {
		t.Fatal("invalid required accepted")
	}
	if err := inspectArbitrarySchema(nil, map[string]struct{}{}, &[]ParamHeaderDefinition{}); err != nil {
		t.Fatal(err)
	}
	if err := inspectArbitrarySchema(json.RawMessage(`{`), map[string]struct{}{}, &[]ParamHeaderDefinition{}); err == nil {
		t.Fatal("invalid object accepted")
	}
	if err := inspectArbitrarySchema(json.RawMessage(`[}`), map[string]struct{}{}, &[]ParamHeaderDefinition{}); err == nil {
		t.Fatal("invalid array accepted")
	}
	if err := inspectArbitrarySchema(json.RawMessage(`[{"x-mcp-header":"X","type":"string"}]`), map[string]struct{}{}, &[]ParamHeaderDefinition{}); err == nil {
		t.Fatal("unreachable array annotation accepted")
	}
	if _, err := encodeResultEnvelope(map[string]json.RawMessage{"bad": json.RawMessage(`{`)}, map[string]json.RawMessage{}); err == nil {
		t.Fatal("invalid envelope encoded")
	}
}

func FuzzTransformToolsList(f *testing.F) {
	f.Add([]byte(toolsResponse(`[]`, "")))
	f.Add([]byte(`{}`))
	f.Fuzz(func(_ *testing.T, body []byte) {
		_, _ = TransformToolsList(body, nil)
	})
}
