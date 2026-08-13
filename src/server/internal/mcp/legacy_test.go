package mcp

import (
	"bytes"
	"testing"
)

func TestUpgradeLegacyResponse(t *testing.T) {
	tests := []struct {
		name, method, body string
		contains           []string
	}{
		{name: "list", method: "tools/list", body: `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`, contains: []string{`"resultType":"complete"`, `"ttlMs":0`, `"cacheScope":"private"`}},
		{name: "call", method: "tools/call", body: `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`, contains: []string{`"resultType":"complete"`, `"content":[]`}},
		{name: "preserves modern fields", method: "prompts/list", body: `{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","prompts":[],"ttlMs":20,"cacheScope":"public"}}`, contains: []string{`"ttlMs":20`, `"cacheScope":"private"`}},
		{name: "error unchanged", method: "tools/list", body: `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"}}`, contains: []string{`"error"`}},
		{name: "notification unchanged", method: "tools/list", body: `{"jsonrpc":"2.0","method":"notifications/progress","params":{}}`, contains: []string{`"notifications/progress"`}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := UpgradeLegacyResponse([]byte(test.body), test.method)
			if err != nil {
				t.Fatal(err)
			}
			for _, wanted := range test.contains {
				if !bytes.Contains(got, []byte(wanted)) {
					t.Fatalf("missing %s in %s", wanted, got)
				}
			}
		})
	}
}

func TestUpgradeLegacyResponseRejectsMalformed(t *testing.T) {
	for _, body := range []string{`{`, `[]`, `{"jsonrpc":"1.0","id":1,"result":{}}`, `{"jsonrpc":"2.0","id":1}`} {
		if _, err := UpgradeLegacyResponse([]byte(body), "tools/call"); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	if !legacyCacheableMethod("resources/list") || !legacyCacheableMethod("resources/templates/list") || legacyCacheableMethod("tools/call") {
		t.Fatal("cacheable method classification")
	}
}
