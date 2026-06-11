package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
)

func TestBlockLinkLocalSplitHostPortError(t *testing.T) {
	// An address with no port triggers a SplitHostPort error, which must be surfaced.
	err := blockLinkLocal("tcp", "169.254.169.254", syscall.RawConn(nil))
	if err == nil {
		t.Fatal("expected error for address missing port")
	}
	if strings.Contains(err.Error(), "refusing") {
		t.Fatalf("expected SplitHostPort error, got block error: %v", err)
	}
}

func TestSafeTransportAllowsLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	t.Run("SafeTransport", func(t *testing.T) {
		c := &http.Client{Transport: SafeTransport(&http.Transport{})}
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatalf("loopback request should succeed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})

	t.Run("DefaultSafeTransport", func(t *testing.T) {
		c := &http.Client{Transport: DefaultSafeTransport()}
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatalf("loopback request should succeed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})
}

func TestSafeTransportRefusesLinkLocalDial(t *testing.T) {
	// A dial to the cloud metadata endpoint must be refused by the Control hook before connecting.
	c := &http.Client{Transport: SafeTransport(&http.Transport{})}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://169.254.169.254:80/latest/meta-data/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("dial to link-local metadata endpoint should be refused")
	}
	if !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("expected link-local refusal, got %v", err)
	}
}
