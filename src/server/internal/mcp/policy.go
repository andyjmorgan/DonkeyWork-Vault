package mcp

import "slices"

// DefaultAction selects the outcome when no explicit policy entry matches.
type DefaultAction string

const (
	// DefaultAllow permits unmatched values.
	DefaultAllow DefaultAction = "allow"
	// DefaultDeny rejects unmatched values.
	DefaultDeny DefaultAction = "deny"
)

// AllowRule applies exact, case-sensitive allow and deny rules to a protocol value.
type AllowRule struct {
	Default DefaultAction
	Allow   []string
	Deny    []string
}

// Policy contains independent method and tool-name rules.
type Policy struct {
	Methods AllowRule
	Tools   AllowRule
}

// Decision is the typed result of evaluating a message against a policy.
type Decision struct {
	Allowed bool
	Field   string
	Value   string
}

// Evaluate applies method policy to every message and tool policy to tools/call requests.
func (p Policy) Evaluate(message ClientMessage) Decision {
	if !p.Methods.allows(message.Audit.Method) {
		return Decision{Field: "method", Value: message.Audit.Method}
	}
	if message.Audit.Method == "tools/call" && !p.Tools.allows(message.Audit.ToolName) {
		return Decision{Field: "tool", Value: message.Audit.ToolName}
	}
	return Decision{Allowed: true}
}

func (rule AllowRule) allows(value string) bool {
	if slices.Contains(rule.Deny, value) {
		return false
	}
	if slices.Contains(rule.Allow, value) {
		return true
	}
	return rule.Default != DefaultDeny
}
