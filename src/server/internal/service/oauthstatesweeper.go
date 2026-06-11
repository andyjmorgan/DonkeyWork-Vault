package service

import (
	"context"
	"log/slog"
	"time"

	"donkeywork.dev/vault-server/internal/store"
)

// oauthStateSweepInterval is how often abandoned oauth_states rows are reaped. The TTL is 10 minutes,
// so a sweep on the same cadence keeps the backlog bounded without hammering the table.
const oauthStateSweepInterval = 10 * time.Minute

// initialOAuthStateSweepDelay is the startup settle time before the first sweep. It is a package var
// so tests can shrink it; production keeps the default.
var initialOAuthStateSweepDelay = time.Minute

// OAuthStateSweeper periodically deletes expired oauth_states rows. DeleteOAuthState only reaps rows
// a callback actually consumes; flows the user abandons (never returning to the callback) leave their
// state rows behind until this sweeper removes them. Storage hygiene only — no security impact.
type OAuthStateSweeper struct {
	store    store.Store
	logger   *slog.Logger
	interval time.Duration
}

// NewOAuthStateSweeper builds the sweeper, defaulting the interval and logger when unset.
func NewOAuthStateSweeper(s store.Store, logger *slog.Logger, interval time.Duration) *OAuthStateSweeper {
	if interval <= 0 {
		interval = oauthStateSweepInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &OAuthStateSweeper{store: s, logger: logger, interval: interval}
}

// Run sweeps on an interval until ctx is cancelled. An initial delay lets startup settle. A failed
// sweep is logged and retried next interval — it never crashes the server.
func (s *OAuthStateSweeper) Run(ctx context.Context) {
	select {
	case <-time.After(initialOAuthStateSweepDelay):
	case <-ctx.Done():
		return
	}
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		s.sweepOnce(ctx)
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// sweepOnce runs a single reap, logging the outcome. Errors are logged at warn (unless ctx was
// cancelled mid-sweep) and swallowed so the loop continues. Exposed for direct testing.
func (s *OAuthStateSweeper) sweepOnce(ctx context.Context) {
	deleted, err := s.store.DeleteExpiredOAuthStates(ctx)
	if err != nil {
		if ctx.Err() == nil {
			s.logger.Warn("oauth state sweep failed; will retry next interval", "err", err)
		}
		return
	}
	if deleted > 0 {
		s.logger.Info("reaped expired oauth states", "count", deleted)
	}
}
