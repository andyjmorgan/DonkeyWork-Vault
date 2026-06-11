package audit

import (
	"net/netip"
	"testing"
)

func TestForwardedIPResolver(t *testing.T) {
	r := NewForwardedIPResolver([]string{"10.0.0.0/8", "bogus", "127.0.0.1"})
	trusted := netip.MustParseAddr("10.1.2.3")
	untrusted := netip.MustParseAddr("8.8.8.8")

	// Trusted peer honours XFF (left-most).
	if got := r.Resolve(trusted, "203.0.113.7, 10.0.0.1", ""); got != "203.0.113.7" {
		t.Fatalf("xff: %s", got)
	}
	// Trusted peer falls back to X-Real-IP.
	if got := r.Resolve(trusted, "", "198.51.100.9:443"); got != "198.51.100.9" {
		t.Fatalf("real-ip: %s", got)
	}
	// Untrusted peer ignores forwarded headers.
	if got := r.Resolve(untrusted, "203.0.113.7", ""); got != "8.8.8.8" {
		t.Fatalf("untrusted: %s", got)
	}
	// Bare /32 trusted host.
	if !r.IsTrusted(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("127.0.0.1 should be trusted")
	}
	// Invalid peer.
	if got := r.Resolve(netip.Addr{}, "", ""); got != "" {
		t.Fatalf("invalid peer: %q", got)
	}
}

func TestStripPort(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:80": "1.2.3.4",
		"[::1]:443":  "::1",
		"::1":        "::1",
		"9.9.9.9":    "9.9.9.9",
	}
	for in, want := range cases {
		if got := stripPort(in); got != want {
			t.Fatalf("stripPort(%q)=%q want %q", in, got, want)
		}
	}
}
