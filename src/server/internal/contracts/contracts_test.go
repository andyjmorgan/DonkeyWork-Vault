package contracts

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestCallerRoundTrip(t *testing.T) {
	u, tn := uuid.New(), uuid.New()
	ctx := WithCaller(context.Background(), Caller{UserID: u, TenantID: tn})
	got := CallerFrom(ctx)
	if got.UserID != u || got.TenantID != tn {
		t.Fatalf("caller mismatch: %+v", got)
	}
	if zero := CallerFrom(context.Background()); zero.UserID != uuid.Nil {
		t.Fatal("expected zero caller")
	}
}

func TestCredentialKindFromWire(t *testing.T) {
	cases := map[string]CredentialKind{
		"opaque": KindOpaque, "header_api_key": KindHeaderAPIKey, "http_basic": KindHTTPBasic,
		"username_password": KindUsernamePassword, "ssh": KindSSH, "connection_string": KindConnectionString,
		"": KindOpaque, "garbage": KindOpaque,
	}
	for in, want := range cases {
		if got := CredentialKindFromWire(in); got != want {
			t.Fatalf("FromWire(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCredentialKindJSON(t *testing.T) {
	b, err := json.Marshal(KindSSH)
	if err != nil || string(b) != `"ssh"` {
		t.Fatalf("marshal: %s %v", b, err)
	}
	// Unknown marshals as opaque.
	b, _ = json.Marshal(CredentialKind("weird"))
	if string(b) != `"opaque"` {
		t.Fatalf("unknown marshal: %s", b)
	}
	var k CredentialKind
	if err := json.Unmarshal([]byte(`"http_basic"`), &k); err != nil || k != KindHTTPBasic {
		t.Fatalf("unmarshal: %q %v", k, err)
	}
	if err := json.Unmarshal([]byte(`123`), &k); err == nil {
		t.Fatal("expected error unmarshaling non-string")
	}
}
