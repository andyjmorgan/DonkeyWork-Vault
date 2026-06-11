package audit

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/store"
	"donkeywork.dev/vault-server/internal/store/memstore"
	"donkeywork.dev/vault-server/internal/telemetry"
)

// TestRetentionRunSweepsThenCancel drives the ticker loop in Run: with a tiny initial delay and a
// short interval, one Sweep executes, then ctx cancellation returns from the loop.
func TestRetentionRunSweepsThenCancel(t *testing.T) {
	orig := initialRetentionDelay
	t.Cleanup(func() { initialRetentionDelay = orig })
	initialRetentionDelay = time.Millisecond

	ms := memstore.New()
	old := store.AuditEntry{CreatedAt: time.Now().AddDate(0, 0, -400), Headers: map[string]string{}}
	_ = ms.InsertAuditBatch(context.Background(), []store.AuditEntry{old})

	r := NewRetention(ms, nil, RetentionOptions{RetentionDays: 180, BatchSize: 10, SweepInterval: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	// Wait for the first sweep to remove the old row, then cancel to exit the loop.
	deadline := time.After(2 * time.Second)
	for ms.AuditCount() != 0 {
		select {
		case <-deadline:
			t.Fatal("sweep did not run")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// TestRetentionSweepError covers the DeleteAuditOlderThan error branch in Sweep.
func TestRetentionSweepError(t *testing.T) {
	ms := memstore.New()
	ms.FailNext = errors.New("delete failed")
	r := NewRetention(ms, nil, RetentionOptions{RetentionDays: 1, BatchSize: 10})
	if err := r.Sweep(context.Background()); err == nil {
		t.Fatal("expected sweep error")
	}
}

// TestForwardedIPEmptyEntryAndInvalidPeer covers the empty-CIDR skip in NewForwardedIPResolver and
// the invalid-peer early return in IsTrusted.
func TestForwardedIPEmptyEntryAndInvalidPeer(t *testing.T) {
	r := NewForwardedIPResolver([]string{"", "  ", "10.0.0.0/8"})
	if r.IsTrusted(netip.Addr{}) {
		t.Fatal("invalid peer must not be trusted")
	}
	if !r.IsTrusted(netip.MustParseAddr("10.1.1.1")) {
		t.Fatal("10.1.1.1 should be trusted")
	}
}

// TestStripPortUnclosedBracket covers the "[" with no closing "]" branch returning v unchanged.
func TestStripPortUnclosedBracket(t *testing.T) {
	if got := stripPort("[::1"); got != "[::1" {
		t.Fatalf("stripPort unclosed bracket = %q", got)
	}
}

// TestRedactHeadersDuplicateKey covers the duplicate lower-cased key skip.
func TestRedactHeadersDuplicateKey(t *testing.T) {
	out := RedactHeaders(map[string][]string{
		"User-Agent": {"first"},
		"user-agent": {"second"}, // same lower-cased key — first occurrence wins, but map order varies
	})
	if len(out) != 1 {
		t.Fatalf("duplicate keys should collapse to one entry, got %d", len(out))
	}
}

// TestLogEnqueueDropWithMetrics covers the metrics-increment branch on a dropped event.
func TestLogEnqueueDropWithMetrics(t *testing.T) {
	metrics, _ := telemetry.NewMetrics()
	l := NewLog(1, nil, metrics)
	l.Enqueue(Event{}) // fills buffer
	l.Enqueue(Event{}) // dropped, metrics path
	if l.DroppedCount() < 1 {
		t.Fatal("expected a drop")
	}
}

// TestEmitWithRecordingSpan covers the span.IsRecording() branch in Emit.
func TestEmitWithRecordingSpan(t *testing.T) {
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("test").Start(context.Background(), "op")
	defer span.End()

	l := NewLog(10, nil, nil)
	l.Emit(ctx, EmitParams{Type: EventTokenAccessed, Outcome: OutcomeSuccess, TargetKind: "k"})
	if len(l.Reader()) == 0 {
		t.Fatal("expected event enqueued")
	}
}

// TestQueryLimitClampLow covers the limit<1 clamp and the Outcome filter, plus the QueryAudit error.
func TestQueryLimitClampLow(t *testing.T) {
	ms := memstore.New()
	u, tn := uuid.New(), uuid.New()
	mk := func(o Outcome) store.AuditEntry {
		return store.AuditEntry{EventType: int(EventAuthFailed), Outcome: int(o), UserID: u, TenantID: tn, CreatedAt: time.Now(), Headers: map[string]string{}}
	}
	_ = ms.InsertAuditBatch(context.Background(), []store.AuditEntry{mk(OutcomeSuccess), mk(OutcomeFailure)})
	l := NewLog(10, nil, nil)
	q := NewQueryService(ms, l)
	ctx := contracts.WithCaller(context.Background(), contracts.Caller{UserID: u, TenantID: tn})

	oc := OutcomeFailure
	res, err := q.Query(ctx, Query{Limit: 0, Outcome: &oc}) // limit<1 clamps to 1; outcome filter applied
	if err != nil {
		t.Fatal(err)
	}
	if res.Limit != 1 {
		t.Fatalf("limit clamp = %d, want 1", res.Limit)
	}
}

func TestQueryStoreError(t *testing.T) {
	ms := memstore.New()
	ms.FailNext = errors.New("query failed")
	l := NewLog(10, nil, nil)
	q := NewQueryService(ms, l)
	ctx := contracts.WithCaller(context.Background(), contracts.Caller{UserID: uuid.New(), TenantID: uuid.New()})
	if _, err := q.Query(ctx, Query{Limit: 10}); err == nil {
		t.Fatal("expected query error")
	}
}

// TestWriterSuccessMetrics covers the AuditWritten metrics branch in persist.
func TestWriterSuccessMetrics(t *testing.T) {
	metrics, _ := telemetry.NewMetrics()
	ms := memstore.New()
	l := NewLog(100, nil, nil)
	w := NewWriter(l, ms, nil, metrics, WriterOptions{BatchSize: 1, FlushInterval: time.Millisecond})
	done := make(chan struct{})
	go func() { w.Run(context.Background()); close(done) }()
	l.Enqueue(Event{Type: EventTokenAccessed, CreatedAt: time.Now(), Headers: map[string]string{}})
	l.Complete()
	<-done
	if ms.AuditCount() != 1 {
		t.Fatalf("expected 1 persisted, got %d", ms.AuditCount())
	}
}

// TestWriterFlushOnTimer covers the ticker.C flush branch: a sub-batch-size set of events is held
// until the flush timer fires (batch size is larger than the number enqueued).
func TestWriterFlushOnTimer(t *testing.T) {
	ms := memstore.New()
	l := NewLog(100, nil, nil)
	w := NewWriter(l, ms, nil, nil, WriterOptions{BatchSize: 100, FlushInterval: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	l.Enqueue(Event{Type: EventTokenAccessed, CreatedAt: time.Now(), Headers: map[string]string{}})

	deadline := time.After(2 * time.Second)
	for ms.AuditCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("timer flush did not persist the event")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

// failStore always fails InsertAuditBatch, forcing persist's retry path so a ctx cancellation during
// the backoff sleep is exercised.
type failStore struct {
	*memstore.Mem
}

func (failStore) InsertAuditBatch(context.Context, []store.AuditEntry) error {
	return errors.New("always fails to force retry/drain paths")
}

// TestWriterCancelDuringRetryBackoff covers the ctx.Done branch inside persist's retry backoff and
// the ctx.Done drain loop (receiving an event then the closed channel) in Run.
func TestWriterCancelDuringRetryBackoff(t *testing.T) {
	fs := failStore{Mem: memstore.New()}
	l := NewLog(100, nil, nil)
	// Long flush interval; large batch so the timer/full-batch flush does not fire — we drive via cancel.
	w := NewWriter(l, fs, nil, nil, WriterOptions{BatchSize: 100, FlushInterval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	for i := 0; i < 3; i++ {
		l.Enqueue(Event{Type: EventAuthFailed, CreatedAt: time.Now(), UserID: uuid.New(), Headers: map[string]string{}})
	}
	time.Sleep(20 * time.Millisecond)
	cancel()     // triggers ctx.Done drain; persist then retries and observes ctx cancellation
	l.Complete() // close so any pending receive sees !ok
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return")
	}
}
