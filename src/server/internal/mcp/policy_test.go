package mcp

import "testing"

func TestPolicyEvaluate(t *testing.T) {
	message := ClientMessage{Audit: AuditFields{Method: "tools/call", ToolName: "search"}}
	tests := []struct {
		name   string
		policy Policy
		allow  bool
		field  string
	}{
		{"zero allows", Policy{}, true, ""},
		{"method default deny", Policy{Methods: AllowRule{Default: DefaultDeny}}, false, "method"},
		{"method allow", Policy{Methods: AllowRule{Default: DefaultDeny, Allow: []string{"tools/call"}}}, true, ""},
		{"method deny wins", Policy{Methods: AllowRule{Allow: []string{"tools/call"}, Deny: []string{"tools/call"}}}, false, "method"},
		{"tool default deny", Policy{Tools: AllowRule{Default: DefaultDeny}}, false, "tool"},
		{"tool allow", Policy{Tools: AllowRule{Default: DefaultDeny, Allow: []string{"search"}}}, true, ""},
		{"tool deny", Policy{Tools: AllowRule{Deny: []string{"search"}}}, false, "tool"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := test.policy.Evaluate(message)
			if decision.Allowed != test.allow || decision.Field != test.field {
				t.Fatalf("got %+v", decision)
			}
			if !decision.Allowed && decision.Value == "" {
				t.Fatal("missing denied value")
			}
		})
	}
	other := Policy{Tools: AllowRule{Default: DefaultDeny}}.Evaluate(ClientMessage{Audit: AuditFields{Method: "resources/read"}})
	if !other.Allowed {
		t.Fatalf("tool policy applied to unrelated method: %+v", other)
	}
}
