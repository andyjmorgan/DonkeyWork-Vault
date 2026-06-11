// Package telemetry wires the three OpenTelemetry pillars — traces, metrics and logs — behind a
// single Setup call. When an OTLP endpoint is configured (OTEL_EXPORTER_OTLP_ENDPOINT or the
// Vault:Telemetry:OTLPEndpoint setting) real OTLP/HTTP exporters are installed; otherwise the
// providers fall back to no-op so the rest of the code can create spans, record metrics and log
// through the OTel pipeline unconditionally and cheaply.
//
// The vault is a credential service, so spans and logs are deliberately attribute-light: we record
// provider slugs, target kinds and outcomes, never secret material, account values or tokens.
package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// ServiceName is the OTel service.name reported for every signal.
const ServiceName = "donkeywork-vault"

// Config controls telemetry setup.
type Config struct {
	// OTLPEndpoint is the OTLP/HTTP collector endpoint (host:port). Empty disables real exporters.
	OTLPEndpoint string
	// Insecure sends OTLP over plaintext HTTP rather than TLS.
	Insecure bool
	// ServiceVersion is reported as service.version.
	ServiceVersion string
	// Environment is reported as deployment.environment.name.
	Environment string
}

// Providers holds the configured OTel providers and a Shutdown that flushes and stops them.
type Providers struct {
	Logger   *slog.Logger
	shutdown func(context.Context) error
}

// Shutdown flushes and stops all providers; safe to call once during graceful shutdown.
func (p *Providers) Shutdown(ctx context.Context) error {
	if p.shutdown == nil {
		return nil
	}
	return p.shutdown(ctx)
}

// Setup installs the global TracerProvider, MeterProvider and a logs LoggerProvider, and returns a
// slog.Logger bridged to OTel logs (also mirrored to stderr for local visibility). It never fails
// hard on a missing collector: without an endpoint it installs no-op-ish providers so the service
// still runs and logs to stderr.
func Setup(ctx context.Context, cfg Config) (*Providers, error) {
	res := buildResource(cfg)

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	var shutdowns []func(context.Context) error
	stderr := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// No endpoint: stderr-only logging, global no-op tracer/meter. Still fully usable.
	if cfg.OTLPEndpoint == "" {
		stderr.Info("telemetry: no OTLP endpoint configured; traces/metrics disabled, logging to stderr")
		return &Providers{Logger: stderr, shutdown: func(context.Context) error { return nil }}, nil
	}

	// OTEL_EXPORTER_OTLP_ENDPOINT is conventionally a full URL (http://host:4318), but the
	// WithEndpoint options want bare host:port — accept both, deriving insecure from the scheme.
	endpoint, insecure := normalizeEndpoint(cfg.OTLPEndpoint, cfg.Insecure)

	// Traces.
	traceOpts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
	if insecure {
		traceOpts = append(traceOpts, otlptracehttp.WithInsecure())
	}
	traceExp, err := otlptracehttp.New(ctx, traceOpts...)
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	shutdowns = append(shutdowns, tp.Shutdown)

	// Metrics.
	metricOpts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpoint(endpoint)}
	if insecure {
		metricOpts = append(metricOpts, otlpmetrichttp.WithInsecure())
	}
	metricExp, err := otlpmetrichttp.New(ctx, metricOpts...)
	if err != nil {
		return nil, err
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp, sdkmetric.WithInterval(30*time.Second))),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)
	shutdowns = append(shutdowns, mp.Shutdown)

	// Logs.
	logOpts := []otlploghttp.Option{otlploghttp.WithEndpoint(endpoint)}
	if insecure {
		logOpts = append(logOpts, otlploghttp.WithInsecure())
	}
	logExp, err := otlploghttp.New(ctx, logOpts...)
	if err != nil {
		return nil, err
	}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)),
		sdklog.WithResource(res),
	)
	shutdowns = append(shutdowns, lp.Shutdown)

	// A logger that fans out to both the OTLP bridge and stderr.
	logger := slog.New(newFanout(
		otelslog.NewHandler(ServiceName, otelslog.WithLoggerProvider(lp)),
		stderr.Handler(),
	))

	return &Providers{
		Logger: logger,
		shutdown: func(ctx context.Context) error {
			var errs []error
			for i := len(shutdowns) - 1; i >= 0; i-- {
				errs = append(errs, shutdowns[i](ctx))
			}
			return errors.Join(errs...)
		},
	}, nil
}

// buildResource assembles the OTel resource describing this service. The custom attributes are
// built schemaless so they merge cleanly onto resource.Default() — a plain resource.NewWithAttributes
// carries the v1.26.0 schema URL, which conflicts with the SDK's baked-in schema URL and makes
// resource.Merge return an error. On that error the old code fell back to resource.Default(), which
// drops service.name entirely (reporting unknown_service:<binary>). Here, if the merge still fails
// for any reason, we fall back to the schemaless attribute resource itself so service.name is never
// lost.
func buildResource(cfg Config) *resource.Resource {
	attrs := resource.NewSchemaless(
		semconv.ServiceName(ServiceName),
		semconv.ServiceVersion(cfg.ServiceVersion),
		attribute.String("deployment.environment.name", cfg.Environment),
	)
	res, err := resource.Merge(resource.Default(), attrs)
	if err != nil {
		return attrs
	}
	return res
}

// normalizeEndpoint accepts either bare host:port or a full http(s):// URL for the OTLP endpoint,
// returning host:port plus whether transport should be insecure (forced by an http:// scheme).
func normalizeEndpoint(endpoint string, insecure bool) (string, bool) {
	switch {
	case strings.HasPrefix(endpoint, "http://"):
		return strings.TrimSuffix(strings.TrimPrefix(endpoint, "http://"), "/"), true
	case strings.HasPrefix(endpoint, "https://"):
		return strings.TrimSuffix(strings.TrimPrefix(endpoint, "https://"), "/"), insecure
	default:
		return endpoint, insecure
	}
}
