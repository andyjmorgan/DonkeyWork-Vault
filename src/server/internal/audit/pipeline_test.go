package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/store"
	"donkeywork.dev/vault-server/internal/store/memstore"
	"donkeywork.dev/vault-server/internal/telemetry"
)

func TestLogEnqueueAndDrop(t *testing.T) {
	l := NewLog(1, nil, nil)
	l.Enqueue(Event{})
	l.Enqueue(Event{})
	l.Enqueue(Event{})
	if l.DroppedCount() < 2 {
		t.Fatalf("expected drops, got %d", l.DroppedCount())
	}
	<-l.Reader()
	l.Complete()
}

func TestLogEmitBuildsEvent(t *testing.T) {
	metrics, _ := telemetry.NewMetrics()
	l := NewLog(10, nil, metrics)
	u, tn := uuid.New(), uuid.New()
	ctx := contracts.WithCaller(context.Background(), contracts.Caller{UserID: u, TenantID: tn})
	ip := "1.2.3.4"
	ctx = WithRequestInfo(ctx, RequestInfo{SourceIP: &ip, Transport: "http", Headers: map[string]string{"a": "b"}})

	for _, tp := range []EventType{EventTokenAccessed, EventTokenRefreshed, EventAuthSucceeded, EventAuditAccessed, EventCredentialCreated} {
		l.Emit(ctx, EmitParams{Type: tp, Outcome: OutcomeSuccess, TargetKind: "k", TargetName: "n"})
	}
	e := <-l.Reader()
	if e.UserID != u || e.SourceIP == nil || *e.SourceIP != ip {
		t.Fatal("event not built from ctx")
	}

	ou, ot := uuid.New(), uuid.New()
	l.Emit(context.Background(), EmitParams{Type: EventTokenAdded, Outcome: OutcomeFailure, UserID: &ou, TenantID: &ot, Detail: "x"})
	for len(l.Reader()) > 0 {
		<-l.Reader()
	}
}

type alwaysFailStore struct{ *memstore.Mem }

func (alwaysFailStore) InsertAuditBatch(context.Context, []store.AuditEntry) error {
	return errors.New("db down")
}

func drainWriter(w *Writer) func() {
	done := make(chan struct{})
	go func() { w.Run(context.Background()); close(done) }()
	return func() { <-done }
}

func TestWriterPersistsBatch(t *testing.T) {
	ms := memstore.New()
	l := NewLog(100, nil, nil)
	w := NewWriter(l, ms, nil, nil, WriterOptions{BatchSize: 2, FlushInterval: 10 * time.Millisecond})
	wait := drainWriter(w)
	for i := 0; i < 5; i++ {
		l.Enqueue(Event{Type: EventTokenAccessed, CreatedAt: time.Now(), Headers: map[string]string{}})
	}
	l.Complete()
	wait()
	if ms.AuditCount() != 5 {
		t.Fatalf("expected 5 persisted, got %d", ms.AuditCount())
	}
}

func TestWriterRetryThenSucceed(t *testing.T) {
	ms := memstore.New()
	ms.FailNext = errors.New("transient")
	l := NewLog(100, nil, nil)
	w := NewWriter(l, ms, nil, nil, WriterOptions{BatchSize: 1, FlushInterval: time.Second})
	wait := drainWriter(w)
	l.Enqueue(Event{Type: EventTokenAccessed, CreatedAt: time.Now(), Headers: map[string]string{}})
	l.Complete()
	wait()
	if ms.AuditCount() != 1 {
		t.Fatalf("expected 1 after retry, got %d", ms.AuditCount())
	}
}

func TestWriterPermanentFailure(t *testing.T) {
	fs := alwaysFailStore{memstore.New()}
	l := NewLog(100, nil, nil)
	w := NewWriter(l, fs, nil, nil, WriterOptions{BatchSize: 1, FlushInterval: time.Millisecond})
	wait := drainWriter(w)
	l.Enqueue(Event{Type: EventAuthFailed, CreatedAt: time.Now(), UserID: uuid.New(), Headers: map[string]string{}})
	l.Complete()
	wait()
}

func TestWriterCancelDrains(t *testing.T) {
	ms := memstore.New()
	l := NewLog(100, nil, nil)
	w := NewWriter(l, ms, nil, nil, WriterOptions{BatchSize: 100, FlushInterval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	for i := 0; i < 3; i++ {
		l.Enqueue(Event{Type: EventTokenAccessed, CreatedAt: time.Now(), Headers: map[string]string{}})
	}
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
	if ms.AuditCount() != 3 {
		t.Fatalf("cancel should drain buffered events, got %d", ms.AuditCount())
	}
}

func TestRetentionSweep(t *testing.T) {
	ms := memstore.New()
	old := store.AuditEntry{CreatedAt: time.Now().AddDate(0, 0, -400), Headers: map[string]string{}}
	recent := store.AuditEntry{CreatedAt: time.Now(), Headers: map[string]string{}}
	_ = ms.InsertAuditBatch(context.Background(), []store.AuditEntry{old, old, recent})
	r := NewRetention(ms, nil, RetentionOptions{RetentionDays: 180, BatchSize: 1})
	if err := r.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ms.AuditCount() != 1 {
		t.Fatalf("expected 1 remaining, got %d", ms.AuditCount())
	}
}

func TestQueryService(t *testing.T) {
	ms := memstore.New()
	u, tn := uuid.New(), uuid.New()
	mk := func(tp EventType) store.AuditEntry {
		return store.AuditEntry{EventType: int(tp), UserID: u, TenantID: tn, CreatedAt: time.Now(), Headers: map[string]string{}}
	}
	_ = ms.InsertAuditBatch(context.Background(), []store.AuditEntry{mk(EventTokenAccessed), mk(EventAuthFailed)})
	l := NewLog(10, nil, nil)
	q := NewQueryService(ms, l)
	ctx := contracts.WithCaller(context.Background(), contracts.Caller{UserID: u, TenantID: tn})

	res, err := q.Query(ctx, Query{Limit: 1000, Offset: -5})
	if err != nil {
		t.Fatal(err)
	}
	if res.Limit != MaxLimit || res.Offset != 0 {
		t.Fatalf("clamping: limit=%d offset=%d", res.Limit, res.Offset)
	}
	if res.Total != 2 {
		t.Fatalf("total=%d", res.Total)
	}
	if len(l.Reader()) == 0 {
		t.Fatal("expected audit-accessed emit")
	}

	tp := EventAuthFailed
	res, _ = q.Query(ctx, Query{Limit: 10, Type: &tp})
	if res.Total != 1 {
		t.Fatalf("filtered total=%d", res.Total)
	}
}

func TestRetentionRunCancel(t *testing.T) {
	ms := memstore.New()
	r := NewRetention(ms, nil, RetentionOptions{}) // defaults applied
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the initial delay elapses
	r.Run(ctx)
}

func TestWriterAndLogDefaults(t *testing.T) {
	// NewWriter/NewLog clamp invalid options.
	l := NewLog(0, nil, nil)
	if l == nil {
		t.Fatal("log")
	}
	w := NewWriter(l, memstore.New(), nil, nil, WriterOptions{})
	if w == nil {
		t.Fatal("writer")
	}
}
