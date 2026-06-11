// Package httpx builds outbound HTTP clients hardened against SSRF for the OAuth/discovery paths,
// where the destination (provider token/userinfo/discovery endpoints) is partly user-controlled
// through stored manifests.
package httpx

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// SafeTransport wraps base with a dialer that refuses connections to link-local addresses — most
// importantly the cloud metadata endpoint (169.254.169.254 / fe80::). It deliberately does NOT
// block private RFC1918 ranges: the vault legitimately reaches in-cluster IdPs and internal
// authorities. The check runs on the post-DNS resolved IP via Dialer.Control, which also defeats
// DNS-rebinding (a hostname that resolves to a link-local address is rejected at connect time).
func SafeTransport(base *http.Transport) *http.Transport {
	t := base.Clone()
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: blockLinkLocal}
	t.DialContext = d.DialContext
	return t
}

func blockLinkLocal(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("refusing to dial non-IP address %q", host)
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("refusing to dial link-local address %s", ip)
	}
	return nil
}

// DefaultSafeTransport is SafeTransport over a clone of http.DefaultTransport.
func DefaultSafeTransport() *http.Transport {
	return SafeTransport(http.DefaultTransport.(*http.Transport))
}
