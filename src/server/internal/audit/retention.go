package audit

import (
	"context"
	"log/slog"
	"time"

	"donkeywork.dev/vault-server/internal/store"
)

// RetentionOptions tune the retention sweeper.
type RetentionOptions struct {
	RetentionDays int
	SweepInterval time.Duration
	BatchSize     int
}

// Retention periodically deletes audit rows older than the hot-retention window, in batches, so the
// append-only table does not grow without bound.
type Retention struct {
	store  store.Store
	logger *slog.Logger
	opts   RetentionOptions
}

// NewRetention builds the sweeper with sane defaults.
func NewRetention(s store.Store, logger *slog.Logger, opts RetentionOptions) *Retention {
	if opts.RetentionDays < 1 {
		opts.RetentionDays = 180
	}
	if opts.SweepInterval <= 0 {
		opts.SweepInterval = 12 * time.Hour
	}
	if opts.BatchSize < 1 {
		opts.BatchSize = 5000
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Retention{store: s, logger: logger, opts: opts}
}

// initialRetentionDelay is the startup settle time before the first sweep. It is a package var so
// tests can shrink it; production keeps the one-minute default.
var initialRetentionDelay = time.Minute

// Run sweeps on an interval until ctx is cancelled. An initial delay lets startup settle.
func (r *Retention) Run(ctx context.Context) {
	select {
	case <-time.After(initialRetentionDelay):
	case <-ctx.Done():
		return
	}
	ticker := time.NewTicker(r.opts.SweepInterval)
	defer ticker.Stop()
	for {
		if err := r.Sweep(ctx); err != nil && ctx.Err() == nil {
			r.logger.Error("audit retention sweep failed; will retry next interval", "err", err)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// Sweep deletes everything older than the cutoff, batch by batch. Exposed for direct testing.
func (r *Retention) Sweep(ctx context.Context) error {
	cutoff := time.Now().UTC().AddDate(0, 0, -r.opts.RetentionDays)
	var total int64
	for ctx.Err() == nil {
		deleted, err := r.store.DeleteAuditOlderThan(ctx, cutoff, r.opts.BatchSize)
		if err != nil {
			return err
		}
		total += deleted
		if deleted < int64(r.opts.BatchSize) {
			break
		}
	}
	if total > 0 {
		r.logger.Info("audit retention removed old rows", "count", total, "days", r.opts.RetentionDays)
	}
	return nil
}
