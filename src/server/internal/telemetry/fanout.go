package telemetry

import (
	"context"
	"log/slog"
)

// fanout is a slog.Handler that dispatches each record to several underlying handlers, so logs can
// go to the OTLP bridge (for the logs pillar, trace-correlated) and to stderr (for local
// visibility) at the same time.
type fanout struct {
	handlers []slog.Handler
}

func newFanout(handlers ...slog.Handler) slog.Handler { return &fanout{handlers: handlers} }

func (f *fanout) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range f.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (f *fanout) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range f.handlers {
		if h.Enabled(ctx, r.Level) {
			// Each handler gets its own clone; ignore individual sink errors so one failing
			// exporter never suppresses the others.
			_ = h.Handle(ctx, r.Clone())
		}
	}
	return nil
}

func (f *fanout) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		next[i] = h.WithAttrs(attrs)
	}
	return &fanout{handlers: next}
}

func (f *fanout) WithGroup(name string) slog.Handler {
	next := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		next[i] = h.WithGroup(name)
	}
	return &fanout{handlers: next}
}
