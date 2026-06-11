package httpapi

import (
	"testing"
	"time"
)

func TestIPRateLimiterWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newIPRateLimiter(3, time.Minute)
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !l.allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if l.allow("1.2.3.4") {
		t.Fatal("4th request in window should be rejected")
	}
	if !l.allow("5.6.7.8") {
		t.Fatal("different IP should have its own budget")
	}

	now = now.Add(time.Minute)
	if !l.allow("1.2.3.4") {
		t.Fatal("new window should reset the budget")
	}
}

func TestRateLimitReturns429(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < rateLimitPerWindow; i++ {
		h.do(t, "GET", "/api/v1/me", nil, true)
	}
	rec := h.do(t, "GET", "/api/v1/me", nil, true)
	if rec.Code != 429 {
		t.Fatalf("want 429 after %d requests, got %d", rateLimitPerWindow, rec.Code)
	}
}
