package audit

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/telemetry"
)

// Log is the bounded, fire-and-forget audit sink. Enqueue writes to a buffered channel and returns
// immediately; when the buffer is full the event is dropped and counted rather than slowing the
// credential path (availability of that path is chosen over guaranteed durability of every row).
type Log struct {
	ch      chan Event
	dropped atomic.Int64
	logger  *slog.Logger
	metrics *telemetry.Metrics
}

// NewLog builds a sink with the given buffer capacity (clamped to >=1).
func NewLog(capacity int, logger *slog.Logger, metrics *telemetry.Metrics) *Log {
	if capacity < 1 {
		capacity = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Log{ch: make(chan Event, capacity), logger: logger, metrics: metrics}
}

// Reader exposes the channel drained by the writer.
func (l *Log) Reader() <-chan Event { return l.ch }

// DroppedCount returns how many events were dropped under back-pressure.
func (l *Log) DroppedCount() int64 { return l.dropped.Load() }

// Enqueue buffers an event without blocking. It never panics on a closed channel.
func (l *Log) Enqueue(e Event) {
	defer func() { _ = recover() }() // never let a closed-channel send reach the caller
	select {
	case l.ch <- e:
	default:
		total := l.dropped.Add(1)
		if l.metrics != nil {
			telemetry.Count(context.Background(), l.metrics.AuditDropped, 1)
		}
		if total == 1 || total%1000 == 0 {
			l.logger.Warn("audit channel full; events dropped", "dropped", total)
		}
	}
}

// Complete closes the channel so the writer can drain and stop.
func (l *Log) Complete() {
	defer func() { _ = recover() }()
	close(l.ch)
}

// EmitParams carries the event-specific fields a domain service supplies; ambient fields (caller,
// IP, redacted headers, key reference) come from the context.
type EmitParams struct {
	Type           EventType
	Outcome        Outcome
	TargetKind     string
	TargetProvider string
	TargetAccount  string
	TargetName     string
	Detail         string
	// UserID/TenantID override the ambient caller (the anonymous OAuth callback supplies them from
	// the state row, since no caller identity exists there).
	UserID   *uuid.UUID
	TenantID *uuid.UUID
}

// Emit builds an event from the ambient context and the supplied params, then enqueues it. It also
// records a span event (traces pillar) and bumps the relevant counter (metrics pillar) so a single
// emit feeds all three signals.
func (l *Log) Emit(ctx context.Context, p EmitParams) {
	caller := contracts.CallerFrom(ctx)
	info := RequestInfoFrom(ctx)

	userID := caller.UserID
	if p.UserID != nil {
		userID = *p.UserID
	}
	tenantID := caller.TenantID
	if p.TenantID != nil {
		tenantID = *p.TenantID
	}

	e := Event{
		Type:            p.Type,
		Outcome:         p.Outcome,
		UserID:          userID,
		TenantID:        tenantID,
		AccessKeyID:     info.AccessKeyID,
		AccessKeyPrefix: info.AccessKeyPrefix,
		AccessKeyName:   info.AccessKeyName,
		SourceIP:        info.SourceIP,
		Headers:         info.Headers,
		TargetKind:      strPtr(p.TargetKind),
		TargetProvider:  strPtr(p.TargetProvider),
		TargetAccount:   strPtr(p.TargetAccount),
		TargetName:      strPtr(p.TargetName),
		Transport:       info.Transport,
		Method:          info.Method,
		Detail:          strPtr(p.Detail),
		CreatedAt:       time.Now().UTC(),
	}

	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.AddEvent("audit", trace.WithAttributes(
			attribute.String("audit.type", p.Type.String()),
			attribute.String("audit.outcome", p.Outcome.String()),
			attribute.String("audit.target_kind", p.TargetKind),
		))
	}
	l.recordMetric(ctx, p)
	l.Enqueue(e)
}

func (l *Log) recordMetric(ctx context.Context, p EmitParams) {
	if l.metrics == nil {
		return
	}
	success := p.Outcome == OutcomeSuccess
	switch p.Type {
	case EventTokenAccessed, EventAuditAccessed:
		telemetry.Count(ctx, l.metrics.CredentialAccessed, 1,
			attribute.String("target_kind", p.TargetKind), telemetry.Outcome(success))
	case EventTokenRefreshed:
		telemetry.Count(ctx, l.metrics.TokenRefreshed, 1, telemetry.Outcome(success))
	case EventAuthSucceeded, EventAuthFailed:
		telemetry.Count(ctx, l.metrics.AuthAttempts, 1, telemetry.Outcome(success))
	}
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
