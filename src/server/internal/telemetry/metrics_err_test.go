package telemetry

import (
	"errors"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/embedded"
	"go.opentelemetry.io/otel/metric/noop"
)

// failingMeter wraps the noop meter but returns an error on the failOn-th instrument creation
// (1-based, counting across all instrument constructors). This drives each error branch in
// NewMetrics without a real collector.
type failingMeter struct {
	noop.Meter // provides all Meter methods; we override the two we use
	failOn     int
	created    int
}

var errInstrument = errors.New("instrument creation failed")

func (m *failingMeter) tick() bool {
	m.created++
	return m.created == m.failOn
}

func (m *failingMeter) Int64Counter(name string, opts ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	if m.tick() {
		return nil, errInstrument
	}
	return m.Meter.Int64Counter(name, opts...)
}

func (m *failingMeter) Float64Histogram(name string, opts ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	if m.tick() {
		return nil, errInstrument
	}
	return m.Meter.Float64Histogram(name, opts...)
}

type failingMeterProvider struct {
	embedded.MeterProvider
	failOn int
}

func (p failingMeterProvider) Meter(string, ...metric.MeterOption) metric.Meter {
	return &failingMeter{failOn: p.failOn}
}

func TestNewMetricsInstrumentErrors(t *testing.T) {
	orig := otel.GetMeterProvider()
	t.Cleanup(func() { otel.SetMeterProvider(orig) })

	// NewMetrics creates 6 instruments in order; fail each one in turn.
	for n := 1; n <= 6; n++ {
		otel.SetMeterProvider(failingMeterProvider{failOn: n})
		if _, err := NewMetrics(); err == nil {
			t.Fatalf("expected error when instrument %d fails", n)
		}
	}
}
