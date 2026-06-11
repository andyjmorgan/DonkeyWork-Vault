package httpx

import (
	"strings"
	"syscall"
	"testing"
)

func TestBlockLinkLocal(t *testing.T) {
	cases := []struct {
		addr    string
		blocked bool
	}{
		{"169.254.169.254:80", true},  // cloud metadata endpoint
		{"169.254.0.1:443", true},     // link-local v4
		{"[fe80::1]:443", true},       // link-local v6
		{"10.0.0.5:443", false},       // RFC1918 — in-cluster IdP must still work
		{"192.168.10.11:6443", false}, // lab subnet
		{"1.1.1.1:443", false},        // public
	}
	for _, c := range cases {
		err := blockLinkLocal("tcp", c.addr, syscall.RawConn(nil))
		if c.blocked && err == nil {
			t.Errorf("%s should be blocked", c.addr)
		}
		if !c.blocked && err != nil {
			t.Errorf("%s should be allowed, got %v", c.addr, err)
		}
	}
}

func TestBlockNonIPHost(t *testing.T) {
	// Control runs post-DNS, so address is always host:port with a resolved IP; a bare hostname
	// would mean resolution was skipped — reject it.
	if err := blockLinkLocal("tcp", "example.com:443", syscall.RawConn(nil)); err == nil || !strings.Contains(err.Error(), "non-IP") {
		t.Fatalf("expected non-IP rejection, got %v", err)
	}
}
