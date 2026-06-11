package httpapi

import (
	"net/http"
	"sync"
	"time"
)

// Request-shedding limits, ported from the .NET host: a fixed-window per-client-IP rate limit on
// /api (rejected with 429 before any auth/DB work) and a request-body size cap (413).

const (
	rateLimitPerWindow = 600
	rateLimitWindow    = time.Minute
	maxRequestBody     = 1 << 20 // 1 MiB — largest legitimate body is a manifest document
)

// ipRateLimiter is a fixed-window counter per client IP. Windows are swept lazily: on each hit an
// expired window resets, and a background-free full sweep runs whenever the map grows past 10k
// entries (bounded memory without a goroutine).
type ipRateLimiter struct {
	mu      sync.Mutex
	windows map[string]*rateWindow
	limit   int
	period  time.Duration
	now     func() time.Time
}

type rateWindow struct {
	start time.Time
	count int
}

func newIPRateLimiter(limit int, period time.Duration) *ipRateLimiter {
	return &ipRateLimiter{windows: make(map[string]*rateWindow), limit: limit, period: period, now: time.Now}
}

// allow records a hit for ip and reports whether it is within the window's budget.
func (l *ipRateLimiter) allow(ip string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.windows) > 10_000 {
		for k, w := range l.windows {
			if now.Sub(w.start) >= l.period {
				delete(l.windows, k)
			}
		}
	}

	w := l.windows[ip]
	if w == nil || now.Sub(w.start) >= l.period {
		l.windows[ip] = &rateWindow{start: now, count: 1}
		return true
	}
	w.count++
	return w.count <= l.limit
}

// limits applies the body cap and per-IP rate limit ahead of authentication.
func (s *Server) limits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ""
		if p := s.resolveIP(r); p != nil {
			ip = *p
		}
		if !s.rate.allow(ip) {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded.")
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}
