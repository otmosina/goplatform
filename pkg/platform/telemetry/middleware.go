package telemetry

// import (
// 	"context"
// 	"fmt"
// 	"net/http"
// 	"time"

// 	"github.com/gin-gonic/gin"
// 	"go.opentelemetry.io/otel"
// 	"go.opentelemetry.io/otel/attribute"
// 	"go.opentelemetry.io/otel/codes"
// 	"go.opentelemetry.io/otel/metric"
// 	"go.opentelemetry.io/otel/propagation"
// 	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
// 	"go.opentelemetry.io/otel/trace"
// )

// // GinOTelTracingMiddleware создает middleware для трейсинга с OpenTelemetry
// func GinOTelTracingMiddleware(serviceName string) gin.HandlerFunc {
// 	tracer := otel.Tracer(serviceName)
// 	propagator := otel.GetTextMapPropagator()

// 	return func(c *gin.Context) {
// 		// Извлекаем контекст из входящих заголовков
// 		ctx := propagator.Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))

// 		// Создаем span
// 		spanName := fmt.Sprintf("%s %s", c.Request.Method, c.FullPath())
// 		ctx, span := tracer.Start(ctx, spanName,
// 			trace.WithSpanKind(trace.SpanKindServer),
// 			trace.WithAttributes(
// 				semconv.HTTPMethod(c.Request.Method),
// 				semconv.HTTPTarget(c.Request.URL.Path),
// 				semconv.HTTPRoute(c.FullPath()),
// 				semconv.HTTPScheme(c.Request.URL.Scheme),
// 				//semconv.HTTPHost(c.Request.Host),
// 				semconv.NetHostName(c.Request.Host),
// 				//semconv.HTTPUserAgent(c.Request.UserAgent()),
// 				semconv.HTTPRequestContentLength(int(c.Request.ContentLength)),
// 				semconv.NetTransportTCP,
// 			),
// 		)
// 		defer span.End()

// 		// Добавляем request ID если есть
// 		if requestID := c.GetString("X-Request-ID"); requestID != "" {
// 			span.SetAttributes(attribute.String("http.request_id", requestID))
// 		}

// 		// Обновляем контекст запроса
// 		c.Request = c.Request.WithContext(ctx)

// 		// Обрабатываем запрос
// 		c.Next()

// 		// Добавляем атрибуты ответа
// 		span.SetAttributes(
// 			semconv.HTTPStatusCode(c.Writer.Status()),
// 			attribute.Int("http.response_size", c.Writer.Size()),
// 		)

// 		// Устанавливаем статус span
// 		if c.Writer.Status() >= 500 {
// 			span.SetStatus(codes.Error, "Internal Server Error")
// 		} else if c.Writer.Status() >= 400 {
// 			span.SetStatus(codes.Error, "Client Error")
// 		} else {
// 			span.SetStatus(codes.Ok, "")
// 		}

// 		// Добавляем ошибки если есть
// 		if len(c.Errors) > 0 {
// 			span.RecordError(c.Errors.Last())
// 			span.SetAttributes(attribute.String("gin.errors", c.Errors.String()))
// 		}
// 	}
// }

// // GinOTelMetricsMiddleware создает middleware для метрик с OpenTelemetry
// func GinOTelMetricsMiddleware(meter metric.Meter) gin.HandlerFunc {
// 	// Создаем инструменты метрик
// 	requestDuration, _ := meter.Float64Histogram(
// 		"http.server.duration",
// 		metric.WithDescription("Duration of HTTP server requests"),
// 		metric.WithUnit("s"),
// 	)

// 	requestCounter, _ := meter.Int64Counter(
// 		"http.server.request_count",
// 		metric.WithDescription("Total number of HTTP requests"),
// 	)

// 	activeRequests, _ := meter.Int64UpDownCounter(
// 		"http.server.active_requests",
// 		metric.WithDescription("Number of active HTTP requests"),
// 	)

// 	requestSize, _ := meter.Int64Histogram(
// 		"http.server.request.size",
// 		metric.WithDescription("Size of HTTP request in bytes"),
// 		metric.WithUnit("By"),
// 	)

// 	responseSize, _ := meter.Int64Histogram(
// 		"http.server.response.size",
// 		metric.WithDescription("Size of HTTP response in bytes"),
// 		metric.WithUnit("By"),
// 	)

// 	return func(c *gin.Context) {
// 		start := time.Now()
// 		path := c.FullPath()
// 		if path == "" {
// 			path = "not_found"
// 		}

// 		// Атрибуты для метрик
// 		attrs := []attribute.KeyValue{
// 			semconv.HTTPMethod(c.Request.Method),
// 			semconv.HTTPRoute(path),
// 			semconv.HTTPScheme(c.Request.URL.Scheme),
// 			attribute.String("net.host.name", c.Request.Host),
// 		}

// 		// Увеличиваем счетчик активных запросов
// 		activeRequests.Add(c.Request.Context(), 1, metric.WithAttributes(attrs...))

// 		// Используем custom ResponseWriter для подсчета размера ответа
// 		rw := &responseWriter{ResponseWriter: c.Writer}
// 		c.Writer = rw

// 		// Обрабатываем запрос
// 		c.Next()

// 		// Уменьшаем счетчик активных запросов
// 		activeRequests.Add(c.Request.Context(), -1, metric.WithAttributes(attrs...))

// 		// Добавляем статус код к атрибутам
// 		attrs = append(attrs, semconv.HTTPStatusCode(c.Writer.Status()))

// 		// Записываем метрики
// 		duration := time.Since(start).Seconds()
// 		requestDuration.Record(c.Request.Context(), duration, metric.WithAttributes(attrs...))
// 		requestCounter.Add(c.Request.Context(), 1, metric.WithAttributes(attrs...))

// 		if c.Request.ContentLength > 0 {
// 			requestSize.Record(c.Request.Context(), c.Request.ContentLength, metric.WithAttributes(attrs...))
// 		}

// 		responseSize.Record(c.Request.Context(), int64(rw.size), metric.WithAttributes(attrs...))
// 	}
// }

// // responseWriter обертка для подсчета размера ответа
// type responseWriter struct {
// 	gin.ResponseWriter
// 	size int
// }

// func (w *responseWriter) Write(data []byte) (int, error) {
// 	size, err := w.ResponseWriter.Write(data)
// 	w.size += size
// 	return size, err
// }

// func (w *responseWriter) WriteString(s string) (int, error) {
// 	size, err := w.ResponseWriter.WriteString(s)
// 	w.size += size
// 	return size, err
// }

// // GinOTelCombinedMiddleware объединяет трейсинг и метрики
// func GinOTelCombinedMiddleware(telemetry *Telemetry) gin.HandlerFunc {
// 	tracingMiddleware := GinOTelTracingMiddleware(telemetry.config.ServiceName)
// 	metricsMiddleware := GinOTelMetricsMiddleware(telemetry.Meter())

// 	return func(c *gin.Context) {
// 		// Сначала применяем трейсинг
// 		tracingMiddleware(c)

// 		// Затем метрики (они используют span из контекста)
// 		metricsMiddleware(c)
// 	}
// }

// // InjectTraceContext внедряет контекст трейсинга в исходящие HTTP запросы
// func InjectTraceContext(ctx context.Context, req *http.Request) {
// 	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))
// }

// // ExtractTraceContext извлекает контекст трейсинга из входящих HTTP запросов
// func ExtractTraceContext(ctx context.Context, req *http.Request) context.Context {
// 	return otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(req.Header))
// }

// // SetSpanError устанавливает ошибку для span
// func SetSpanError(span trace.Span, err error) {
// 	span.RecordError(err)
// 	span.SetStatus(codes.Error, err.Error())
// }

// // SetSpanAttributes добавляет атрибуты к span
// func SetSpanAttributes(span trace.Span, attrs ...attribute.KeyValue) {
// 	span.SetAttributes(attrs...)
// }

// // SpanWithAttributes создает span с атрибутами
// func SpanWithAttributes(ctx context.Context, spanName string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
// 	return otel.Tracer("").Start(ctx, spanName, trace.WithAttributes(attrs...))
// }
