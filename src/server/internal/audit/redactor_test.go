package audit

import "testing"

func TestRedactHeader(t *testing.T) {
	if RedactHeader("Authorization", "Bearer x") != Redacted {
		t.Fatal("authorization must be redacted")
	}
	if RedactHeader("User-Agent", "curl") != "curl" {
		t.Fatal("user-agent allowlisted")
	}
	if RedactHeader("X-Custom", "v") != Redacted {
		t.Fatal("non-allowlisted redacted")
	}
	if RedactHeader("", "v") != Redacted {
		t.Fatal("empty name redacted")
	}
	if RedactHeader("X-Session-Token", "v") != Redacted {
		t.Fatal("token pattern redacted")
	}
	if RedactHeader("My-Api-Key", "v") != Redacted {
		t.Fatal("-key suffix redacted")
	}
}

func TestRedactHeaders(t *testing.T) {
	in := map[string][]string{
		"User-Agent":      {"curl"},
		"Authorization":   {"secret"},
		"":                {"x"},
		"X-Forwarded-For": {"1.2.3.4"},
	}
	out := RedactHeaders(in)
	if out["user-agent"] != "curl" || out["authorization"] != Redacted {
		t.Fatalf("redaction: %v", out)
	}
	if _, ok := out[""]; ok {
		t.Fatal("empty key should be dropped")
	}
}

func TestIsDenied(t *testing.T) {
	for _, n := range []string{"cookie", "X-Password-Hint", "my-secret", "session-token", "foo-key"} {
		if !IsDenied(n) {
			t.Fatalf("%s should be denied", n)
		}
	}
	if IsDenied("accept") {
		t.Fatal("accept not denied")
	}
}
