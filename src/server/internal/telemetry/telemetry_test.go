package telemetry

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

func TestSetupNoEndpoint(t *testing.T) {
	p, err := Setup(context.Background(), Config{ServiceVersion: "test", Environment: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Logger == nil {
		t.Fatal("logger")
	}
	p.Logger.Info("hello", "k", "v")
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Shutdown is safe with a nil func too.
	(&Providers{}).Shutdown(context.Background())
}

func TestMetricsAndHelpers(t *testing.T) {
	m, err := NewMetrics()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	Count(ctx, m.CredentialAccessed, 1, Outcome(true))
	Count(ctx, m.AuditDropped, 1, Outcome(false))
	Count(ctx, nil, 1) // nil-safe no-op
	if Outcome(true).Value.AsString() != "success" || Outcome(false).Value.AsString() != "failure" {
		t.Fatal("outcome attr")
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func TestFanout(t *testing.T) {
	base := slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: slog.LevelInfo})
	h := newFanout(base)
	l := slog.New(h.WithAttrs([]slog.Attr{slog.String("a", "b")}).WithGroup("g"))
	l.Info("msg", "x", 1)
	l.Debug("filtered") // below level on all handlers
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("error level should be enabled")
	}
}

func TestSetupWithOTLPEndpoint(t *testing.T) {
	p, err := Setup(context.Background(), Config{OTLPEndpoint: "127.0.0.1:4318", Insecure: true, ServiceVersion: "v", Environment: "test"})
	if err != nil {
		t.Fatalf("setup with endpoint: %v", err)
	}
	if p.Logger == nil {
		t.Fatal("logger")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = p.Shutdown(ctx) // collector is absent; flush errors are tolerated
}
