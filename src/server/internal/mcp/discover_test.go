package mcp

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

var testGatewayIdentity = GatewayIdentity{
	Name: "DonkeyWork Vault", Version: "1.2.3", Description: "MCP gateway", WebsiteURL: "https://vault.example",
}

func discoverResponse(capabilities string) string {
	return `{"jsonrpc":"2.0","id":"discover-1","result":{"resultType":"complete","supportedVersions":["old"],"capabilities":` + capabilities + `,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"upstream","version":"secret"}},"instructions":"preserve this","ttlMs":3600,"cacheScope":"public","vendor":"kept"}}`
}

func TestTransformDiscover(t *testing.T) {
	body := discoverResponse(`{"tools":{"listChanged":true},"resources":{"subscribe":true},"com.example/extension":{"enabled":true}}`)
	transformed, err := TransformDiscover([]byte(body), testGatewayIdentity, func(name string) bool { return name != "resources" })
	if err != nil {
		t.Fatal(err)
	}
	if !transformed.Filtered || !reflect.DeepEqual([]string{transformed.Capabilities[0].Name, transformed.Capabilities[1].Name}, []string{"com.example/extension", "tools"}) {
		t.Fatalf("unexpected capabilities: %+v", transformed)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(transformed.Body, &envelope); err != nil {
		t.Fatal(err)
	}
	result, _, _ := optionalObject(envelope, "result")
	if string(result["supportedVersions"]) != `["2026-07-28"]` || string(result["cacheScope"]) != `"private"` {
		t.Fatalf("version/scope incorrect: %s", transformed.Body)
	}
	if string(result["instructions"]) != `"preserve this"` || string(result["vendor"]) != `"kept"` {
		t.Fatalf("metadata lost: %s", transformed.Body)
	}
	meta, _, _ := optionalObject(result, "_meta")
	serverInfo, _, _ := optionalObject(meta, "io.modelcontextprotocol/serverInfo")
	if name, _ := optionalString(serverInfo, "name"); name != testGatewayIdentity.Name {
		t.Fatalf("upstream identity leaked: %s", transformed.Body)
	}
	capabilities, _, _ := optionalObject(result, "capabilities")
	if _, exists := capabilities["resources"]; exists {
		t.Fatalf("blocked capability retained: %s", transformed.Body)
	}
}

func TestTransformDiscoverNoFiltering(t *testing.T) {
	transformed, err := TransformDiscover([]byte(discoverResponse(`{"tools":{}}`)), GatewayIdentity{Name: "gateway", Version: "1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if transformed.Filtered || !strings.Contains(string(transformed.Body), `"cacheScope":"public"`) {
		t.Fatalf("scope changed: %+v %s", transformed, transformed.Body)
	}
}

func TestTransformDiscoverInvalid(t *testing.T) {
	valid := discoverResponse(`{"tools":{}}`)
	tests := []struct {
		name     string
		body     string
		identity GatewayIdentity
	}{
		{"identity", valid, GatewayIdentity{}},
		{"envelope", `{}`, testGatewayIdentity},
		{"cache", strings.Replace(valid, `"ttlMs":3600`, `"ttlMs":-1`, 1), testGatewayIdentity},
		{"missing capabilities", strings.Replace(valid, `"capabilities":{"tools":{}},`, "", 1), testGatewayIdentity},
		{"capabilities array", strings.Replace(valid, `"capabilities":{"tools":{}}`, `"capabilities":[]`, 1), testGatewayIdentity},
		{"capability value", discoverResponse(`{"tools":true}`), testGatewayIdentity},
		{"capability name", discoverResponse(`{"bad name":{}}`), testGatewayIdentity},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := TransformDiscover([]byte(test.body), test.identity, nil); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestBuildDiscover(t *testing.T) {
	body, err := BuildDiscover(ID{Kind: IDNumber, Value: "7"}, testGatewayIdentity, []Capability{
		{Name: "tools", Settings: json.RawMessage(`{"listChanged":true}`)},
		{Name: "resources", Settings: json.RawMessage(`{}`)},
	}, 1000)
	if err != nil {
		t.Fatal(err)
	}
	server, err := InspectServer(body, nil)
	if err != nil || server.ID != (ID{Kind: IDNumber, Value: "7"}) || server.Kind != KindResult {
		t.Fatalf("invalid result: %+v %v: %s", server, err, body)
	}
	var envelope map[string]json.RawMessage
	_ = json.Unmarshal(body, &envelope)
	result, _, _ := optionalObject(envelope, "result")
	if string(result["resultType"]) != `"complete"` || string(result["supportedVersions"]) != `["2026-07-28"]` || string(result["ttlMs"]) != "1000" || string(result["cacheScope"]) != `"private"` {
		t.Fatalf("wrong discover result: %s", body)
	}

	stringBody, err := BuildDiscover(ID{Kind: IDString, Value: "discover"}, GatewayIdentity{Name: "gateway", Version: "1"}, nil, 0)
	if err != nil || !strings.Contains(string(stringBody), `"id":"discover"`) {
		t.Fatalf("string ID failed: %v %s", err, stringBody)
	}
}

func TestBuildDiscoverInvalid(t *testing.T) {
	tests := []struct {
		name         string
		id           ID
		identity     GatewayIdentity
		capabilities []Capability
		ttl          int64
	}{
		{"identity", ID{Kind: IDNumber, Value: "1"}, GatewayIdentity{}, nil, 0},
		{"id kind", ID{Kind: IDNone}, testGatewayIdentity, nil, 0},
		{"empty id", ID{Kind: IDString}, testGatewayIdentity, nil, 0},
		{"bad number", ID{Kind: IDNumber, Value: "not-number"}, testGatewayIdentity, nil, 0},
		{"object number", ID{Kind: IDNumber, Value: `{}`}, testGatewayIdentity, nil, 0},
		{"ttl", ID{Kind: IDNumber, Value: "1"}, testGatewayIdentity, nil, -1},
		{"capability name", ID{Kind: IDNumber, Value: "1"}, testGatewayIdentity, []Capability{{Name: "bad name", Settings: json.RawMessage(`{}`)}}, 0},
		{"duplicate", ID{Kind: IDNumber, Value: "1"}, testGatewayIdentity, []Capability{{Name: "tools", Settings: json.RawMessage(`{}`)}, {Name: "tools", Settings: json.RawMessage(`{}`)}}, 0},
		{"settings", ID{Kind: IDNumber, Value: "1"}, testGatewayIdentity, []Capability{{Name: "tools", Settings: json.RawMessage(`true`)}}, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := BuildDiscover(test.id, test.identity, test.capabilities, test.ttl)
			var target *TransformError
			if !errors.As(err, &target) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestGatewayIdentityOptionalFields(t *testing.T) {
	encoded, err := gatewayMeta(GatewayIdentity{Name: "gateway", Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "description") || strings.Contains(string(encoded), "websiteUrl") {
		t.Fatalf("unexpected optional fields: %s", encoded)
	}
}

func TestCapabilityName(t *testing.T) {
	if validCapabilityName("") || validCapabilityName("bad\x7f") || validCapabilityName("bad name") || !validCapabilityName("com.example/feature") {
		t.Fatal("capability name validation mismatch")
	}
}

func FuzzTransformDiscover(f *testing.F) {
	f.Add([]byte(discoverResponse(`{"tools":{}}`)))
	f.Add([]byte(`null`))
	f.Fuzz(func(_ *testing.T, body []byte) {
		_, _ = TransformDiscover(body, testGatewayIdentity, nil)
	})
}
