package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metrics holds the vault's custom instruments. They are created against the global MeterProvider,
// so they record into whatever provider Setup installed (real OTLP or no-op). None of these
// instruments carry secret material — only low-cardinality dimensions like outcome and target kind.
type Metrics struct {
	CredentialAccessed metric.Int64Counter     // credential/token reads, dim: target_kind, outcome
	TokenRefreshed     metric.Int64Counter     // oauth refresh attempts, dim: outcome
	AuthAttempts       metric.Int64Counter     // auth outcomes, dim: scheme, outcome
	AuditDropped       metric.Int64Counter     // audit events dropped under back-pressure
	AuditWritten       metric.Int64Counter     // audit events persisted
	ServiceLatency     metric.Float64Histogram // service-method latency in ms, dim: operation
}

// NewMetrics builds the instrument set. It returns an error only if instrument creation fails.
func NewMetrics() (*Metrics, error) {
	m := otel.Meter(ServiceName)
	var err error
	mm := &Metrics{}

	if mm.CredentialAccessed, err = m.Int64Counter("vault.credential.accessed",
		metric.WithDescription("Count of credential/token read attempts")); err != nil {
		return nil, err
	}
	if mm.TokenRefreshed, err = m.Int64Counter("vault.oauth.refreshed",
		metric.WithDescription("Count of OAuth token refresh attempts")); err != nil {
		return nil, err
	}
	if mm.AuthAttempts, err = m.Int64Counter("vault.auth.attempts",
		metric.WithDescription("Count of authentication attempts by scheme and outcome")); err != nil {
		return nil, err
	}
	if mm.AuditDropped, err = m.Int64Counter("vault.audit.dropped",
		metric.WithDescription("Audit events dropped due to channel back-pressure")); err != nil {
		return nil, err
	}
	if mm.AuditWritten, err = m.Int64Counter("vault.audit.written",
		metric.WithDescription("Audit events persisted to the trail")); err != nil {
		return nil, err
	}
	if mm.ServiceLatency, err = m.Float64Histogram("vault.service.latency",
		metric.WithDescription("Service-method latency"), metric.WithUnit("ms")); err != nil {
		return nil, err
	}
	return mm, nil
}

// Outcome is a small helper for the standard success/failure dimension.
func Outcome(success bool) attribute.KeyValue {
	if success {
		return attribute.String("outcome", "success")
	}
	return attribute.String("outcome", "failure")
}

// Count is a nil-safe counter increment (instruments may be nil in tests that skip telemetry).
func Count(ctx context.Context, c metric.Int64Counter, n int64, attrs ...attribute.KeyValue) {
	if c == nil {
		return
	}
	c.Add(ctx, n, metric.WithAttributes(attrs...))
}
