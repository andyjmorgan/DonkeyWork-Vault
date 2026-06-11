package audit

import (
	"context"
	"log/slog"
	"time"

	"donkeywork.dev/vault-server/internal/store"
	"donkeywork.dev/vault-server/internal/telemetry"
)

// WriterOptions tune the batch writer.
type WriterOptions struct {
	BatchSize     int
	FlushInterval time.Duration
}

// Writer drains the Log channel and bulk-inserts batched events on its own store handle — never the
// request's — so writes never block the credential hot path. On DB failure it retries with backoff
// and, as a last resort, logs the (already-redacted) events rather than wedging the channel.
type Writer struct {
	log     *Log
	store   store.Store
	logger  *slog.Logger
	metrics *telemetry.Metrics
	opts    WriterOptions
}

// NewWriter builds the writer.
func NewWriter(log *Log, s store.Store, logger *slog.Logger, metrics *telemetry.Metrics, opts WriterOptions) *Writer {
	if opts.BatchSize < 1 {
		opts.BatchSize = 100
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 500 * time.Millisecond
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Writer{log: log, store: s, logger: logger, metrics: metrics, opts: opts}
}

// Run drains until the channel is closed (Log.Complete), then returns. Intended to run in its own
// goroutine. ctx bounds the DB work; cancelling it stops retries.
func (w *Writer) Run(ctx context.Context) {
	reader := w.log.Reader()
	batch := make([]Event, 0, w.opts.BatchSize)
	ticker := time.NewTicker(w.opts.FlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		w.persist(ctx, batch)
		batch = batch[:0]
	}

	for {
		select {
		case e, ok := <-reader:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= w.opts.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-ctx.Done():
			flush()
			return
		}
	}
}

func (w *Writer) persist(ctx context.Context, batch []Event) {
	const maxAttempts = 4
	entries := make([]store.AuditEntry, len(batch))
	for i, e := range batch {
		entries[i] = toEntry(e)
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := w.store.InsertAuditBatch(ctx, entries)
		if err == nil {
			if w.metrics != nil {
				telemetry.Count(ctx, w.metrics.AuditWritten, int64(len(entries)))
			}
			return
		}
		if attempt < maxAttempts && ctx.Err() == nil {
			delay := time.Duration(200*(1<<(attempt-1))) * time.Millisecond
			w.logger.Warn("audit batch insert failed; retrying", "attempt", attempt, "delay", delay, "err", err)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
			continue
		}
		// Last resort: emit the already-redacted events to the log so the trail is not silently lost.
		w.logger.Error("audit batch insert failed permanently; dropping", "count", len(batch), "err", err)
		for _, e := range batch {
			w.logger.Warn("AUDIT(unpersisted)",
				slog.String("type", e.Type.String()),
				slog.String("outcome", e.Outcome.String()),
				slog.String("user", e.UserID.String()),
				slog.Any("target_kind", e.TargetKind),
				slog.Any("method", e.Method),
				slog.Any("detail", e.Detail))
		}
		return
	}
}

func toEntry(e Event) store.AuditEntry {
	return store.AuditEntry{
		EventType:       int(e.Type),
		Outcome:         int(e.Outcome),
		UserID:          e.UserID,
		TenantID:        e.TenantID,
		AccessKeyID:     e.AccessKeyID,
		AccessKeyPrefix: e.AccessKeyPrefix,
		AccessKeyName:   e.AccessKeyName,
		SourceIP:        e.SourceIP,
		Headers:         e.Headers,
		TargetKind:      e.TargetKind,
		TargetProvider:  e.TargetProvider,
		TargetAccount:   e.TargetAccount,
		TargetName:      e.TargetName,
		Transport:       e.Transport,
		Method:          e.Method,
		Detail:          e.Detail,
		CreatedAt:       e.CreatedAt,
	}
}

