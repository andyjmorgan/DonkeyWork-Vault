package audit

import (
	"net/netip"
	"strings"
)

// ForwardedIPResolver resolves the real client IP behind ingress using a trusted-proxy policy:
// forwarded headers (X-Forwarded-For left-most, then X-Real-IP) are honoured only when the immediate
// socket peer is within the configured trusted ranges; otherwise the socket peer is used. This stops
// a client spoofing X-Forwarded-For to forge the audited source IP.
type ForwardedIPResolver struct {
	trusted []netip.Prefix
}

// NewForwardedIPResolver parses CIDR strings (bare addresses become /32 or /128), ignoring malformed
// entries.
func NewForwardedIPResolver(cidrs []string) *ForwardedIPResolver {
	var nets []netip.Prefix
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if p, err := netip.ParsePrefix(c); err == nil {
			nets = append(nets, p)
			continue
		}
		if a, err := netip.ParseAddr(c); err == nil {
			nets = append(nets, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return &ForwardedIPResolver{trusted: nets}
}

// IsTrusted reports whether the peer falls within a trusted range.
func (r *ForwardedIPResolver) IsTrusted(peer netip.Addr) bool {
	if !peer.IsValid() {
		return false
	}
	peer = peer.Unmap()
	for _, n := range r.trusted {
		if n.Contains(peer) {
			return true
		}
	}
	return false
}

// Resolve returns the client IP as a string. Forwarded headers are honoured only from a trusted peer.
// Returns "" when nothing usable is available.
func (r *ForwardedIPResolver) Resolve(peer netip.Addr, xForwardedFor, xRealIP string) string {
	if peer.IsValid() && r.IsTrusted(peer) {
		for _, hop := range strings.Split(xForwardedFor, ",") {
			hop = strings.TrimSpace(hop)
			if hop == "" {
				continue
			}
			if a, err := netip.ParseAddr(stripPort(hop)); err == nil {
				return a.Unmap().String()
			}
		}
		if xRealIP = strings.TrimSpace(xRealIP); xRealIP != "" {
			if a, err := netip.ParseAddr(stripPort(xRealIP)); err == nil {
				return a.Unmap().String()
			}
		}
	}
	if peer.IsValid() {
		return peer.Unmap().String()
	}
	return ""
}

// stripPort removes a trailing :port (and []-brackets for IPv6) from a host[:port] token.
func stripPort(v string) string {
	if strings.HasPrefix(v, "[") {
		if end := strings.IndexByte(v, ']'); end > 0 {
			return v[1:end]
		}
		return v
	}
	// IPv4 with a port: 1.2.3.4:5678. A bare IPv6 has multiple colons, so leave it.
	if first := strings.IndexByte(v, ':'); first > 0 && strings.IndexByte(v[first+1:], ':') < 0 {
		return v[:first]
	}
	return v
}
