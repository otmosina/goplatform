package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// Config конфигурация телеметрии
type Config struct {
	ServiceName    string
	ServiceVersion string
	Environment    string
	ExporterType   ExporterType
	Endpoint       string
	SamplingRate   float64
	EnableMetrics  bool
	EnableTracing  bool
	Headers        map[string]string
	Insecure       bool
}

// ExporterType тип экспортера
type ExporterType string

const (
	ExporterJaeger     ExporterType = "jaeger"
	ExporterOTLPGRPC   ExporterType = "otlp-grpc"
	ExporterOTLPHTTP   ExporterType = "otlp-http"
	ExporterPrometheus ExporterType = "prometheus"
)

// Telemetry структура для работы с телеметрией
type Telemetry struct {
	config         *Config
	tracer         trace.Tracer
	meter          metric.Meter
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *metric.MeterProvider
}

// New создает новый экземпляр телеметрии
func New(config *Config) (*Telemetry, error) {
	telemetry := &Telemetry{
		config: config,
	}

	// Создаем ресурс
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(config.ServiceName),
			semconv.ServiceVersion(config.ServiceVersion),
			attribute.String("environment", config.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Инициализируем трейсинг
	if config.EnableTracing {
		if err := telemetry.initTracing(res); err != nil {
			return nil, fmt.Errorf("failed to init tracing: %w", err)
		}
	}

	// Инициализируем метрики
	if config.EnableMetrics {
		if err := telemetry.initMetrics(res); err != nil {
			return nil, fmt.Errorf("failed to init metrics: %w", err)
		}
	}

	return telemetry, nil
}

// initTracing инициализирует трейсинг
func (t *Telemetry) initTracing(res *resource.Resource) error {
	var exporter sdktrace.SpanExporter
	var err error

	switch t.config.ExporterType {
	case ExporterJaeger:
		exporter, err = jaeger.New(
			jaeger.WithAgentEndpoint(
				jaeger.WithAgentHost(getHost(t.config.Endpoint)),
				jaeger.WithAgentPort(getPort(t.config.Endpoint)),
			),
		)
	case ExporterOTLPGRPC:
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(t.config.Endpoint),
		}
		if t.config.Insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		if len(t.config.Headers) > 0 {
			opts = append(opts, otlptracegrpc.WithHeaders(t.config.Headers))
		}
		client := otlptracegrpc.NewClient(opts...)
		exporter, err = otlptrace.New(context.Background(), client)
	case ExporterOTLPHTTP:
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(t.config.Endpoint),
		}
		if t.config.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		if len(t.config.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(t.config.Headers))
		}
		client := otlptracehttp.NewClient(opts...)
		exporter, err = otlptrace.New(context.Background(), client)
	default:
		return fmt.Errorf("unsupported tracer exporter type: %s", t.config.ExporterType)
	}

	if err != nil {
		return fmt.Errorf("failed to create exporter: %w", err)
	}

	t.tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(t.config.SamplingRate)),
	)

	otel.SetTracerProvider(t.tracerProvider)
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	)

	t.tracer = t.tracerProvider.Tracer(t.config.ServiceName)

	return nil
}

// initMetrics инициализирует метрики
func (t *Telemetry) initMetrics(res *resource.Resource) error {
	// Создаем Prometheus exporter
	prometheusExporter, err := prometheus.New()
	if err != nil {
		return fmt.Errorf("failed to create prometheus exporter: %w", err)
	}

	t.meterProvider = metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(prometheusExporter),
	)

	otel.SetMeterProvider(t.meterProvider)
	t.meter = t.meterProvider.Meter(t.config.ServiceName)

	return nil
}

// Tracer возвращает трейсер
func (t *Telemetry) Tracer() trace.Tracer {
	if t.tracer == nil {
		return otel.Tracer(t.config.ServiceName)
	}
	return t.tracer
}

// Meter возвращает meter для метрик
func (t *Telemetry) Meter() metric.Meter {
	if t.meter == nil {
		return otel.Meter(t.config.ServiceName)
	}
	return t.meter
}

// Shutdown корректно завершает работу телеметрии
func (t *Telemetry) Shutdown(ctx context.Context) error {
	if t.tracerProvider != nil {
		if err := t.tracerProvider.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown tracer provider: %w", err)
		}
	}

	if t.meterProvider != nil {
		if err := t.meterProvider.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown meter provider: %w", err)
		}
	}

	return nil
}

// StartSpan создает новый span
func (t *Telemetry) StartSpan(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return t.Tracer().Start(ctx, spanName, opts...)
}

// SpanFromContext получает span из контекста
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// WithSpan выполняет функцию в контексте span
func (t *Telemetry) WithSpan(ctx context.Context, spanName string, fn func(context.Context) error, opts ...trace.SpanStartOption) error {
	ctx, span := t.StartSpan(ctx, spanName, opts...)
	defer span.End()

	err := fn(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(trace.StatusCode(trace.StatusError), err.Error())
	}

	return err
}

// Helper функции
func getHost(endpoint string) string {
	// Простая реализация, можно улучшить
	if endpoint == "" {
		return "localhost"
	}
	return endpoint
}

func getPort(endpoint string) string {
	// Простая реализация, можно улучшить
	return "6831"
}
