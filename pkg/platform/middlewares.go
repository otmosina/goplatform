package platform

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/time/rate"
)

// requestIDKey ключ для хранения request ID в контексте
const requestIDKey = "X-Request-ID"

// Prometheus метрики (инициализируются один раз)
var (
	httpDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "http",
			Subsystem: "requests",
			Name:      "duration_seconds",
			Help:      "Duration of HTTP requests in seconds",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"method", "path", "status"},
	)

	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "http",
			Subsystem: "requests",
			Name:      "total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	httpRequestSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "http",
			Subsystem: "requests",
			Name:      "size_bytes",
			Help:      "Size of HTTP requests in bytes",
			Buckets:   prometheus.ExponentialBuckets(100, 10, 7), // 100B to 100MB
		},
		[]string{"method", "path"},
	)

	httpResponseSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "http",
			Subsystem: "responses",
			Name:      "size_bytes",
			Help:      "Size of HTTP responses in bytes",
			Buckets:   prometheus.ExponentialBuckets(100, 10, 7),
		},
		[]string{"method", "path", "status"},
	)

	httpActiveRequests = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "http",
			Subsystem: "requests",
			Name:      "active",
			Help:      "Number of active HTTP requests",
		},
		[]string{"method", "path"},
	)
)

// GinRequestID middleware для генерации и добавления request ID
func GinRequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Проверяем, есть ли уже request ID в заголовках
		requestID := c.GetHeader(requestIDKey)
		if requestID == "" {
			// Генерируем новый UUID
			requestID = uuid.New().String()
		}

		// Сохраняем в контексте Gin
		c.Set(requestIDKey, requestID)

		// Добавляем в заголовки ответа
		c.Header(requestIDKey, requestID)

		c.Next()
	}
}

// GinLoggingMiddleware создает Gin middleware для логирования
func GinLoggingMiddleware(logger Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Получаем request ID
		requestID, _ := c.Get(requestIDKey)

		// Создаем запросный логгер
		requestLogger := logger.WithFields(map[string]interface{}{
			"method":     c.Request.Method,
			"path":       path,
			"remote_ip":  c.ClientIP(),
			"user_agent": c.Request.UserAgent(),
			"request_id": requestID,
		})

		// Добавляем логгер в контекст
		ctx := requestLogger.ToContext(c.Request.Context())
		c.Request = c.Request.WithContext(ctx)

		// Обрабатываем запрос
		c.Next()

		// Логируем результат
		duration := time.Since(start)
		fields := map[string]interface{}{
			"status":      c.Writer.Status(),
			"size":        c.Writer.Size(),
			"duration":    duration.String(),
			"duration_ms": duration.Milliseconds(),
		}

		if raw != "" {
			fields["query"] = raw
		}

		// Добавляем ошибки если есть
		if len(c.Errors) > 0 {
			fields["errors"] = c.Errors.String()
		}

		// Логируем в зависимости от статуса
		switch {
		case c.Writer.Status() >= 500:
			requestLogger.WithFields(fields).Error("HTTP request failed")
		case c.Writer.Status() >= 400:
			requestLogger.WithFields(fields).Warn("HTTP request client error")
		default:
			requestLogger.WithFields(fields).Info("HTTP request completed")
		}
	}
}

// GinMetricsMiddleware создает Gin middleware для сбора метрик
func GinMetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.FullPath() // Используем шаблон пути, а не фактический путь
		if path == "" {
			path = "not_found"
		}
		method := c.Request.Method

		// Считаем размер запроса
		var requestSize float64
		if c.Request.ContentLength > 0 {
			requestSize = float64(c.Request.ContentLength)
		}

		// Увеличиваем счетчик активных запросов
		httpActiveRequests.WithLabelValues(method, path).Inc()

		// Используем custom ResponseWriter для подсчета размера ответа
		rw := &responseWriter{ResponseWriter: c.Writer}
		c.Writer = rw

		// Обрабатываем запрос
		c.Next()

		// Уменьшаем счетчик активных запросов
		httpActiveRequests.WithLabelValues(method, path).Dec()

		// Собираем метрики
		duration := time.Since(start).Seconds()
		status := fmt.Sprintf("%d", c.Writer.Status())

		httpDuration.WithLabelValues(method, path, status).Observe(duration)
		httpRequestsTotal.WithLabelValues(method, path, status).Inc()
		httpRequestSize.WithLabelValues(method, path).Observe(requestSize)
		httpResponseSize.WithLabelValues(method, path, status).Observe(float64(rw.size))
	}
}

// responseWriter обертка для подсчета размера ответа
type responseWriter struct {
	gin.ResponseWriter
	size int
}

func (w *responseWriter) Write(data []byte) (int, error) {
	size, err := w.ResponseWriter.Write(data)
	w.size += size
	return size, err
}

func (w *responseWriter) WriteString(s string) (int, error) {
	size, err := w.ResponseWriter.WriteString(s)
	w.size += size
	return size, err
}

// GinTracingMiddleware создает Gin middleware для трейсинга
func GinTracingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tracer := opentracing.GlobalTracer()

		// Извлекаем span context из заголовков
		var spanCtx opentracing.SpanContext
		carrier := opentracing.HTTPHeadersCarrier(c.Request.Header)
		spanCtx, _ = tracer.Extract(opentracing.HTTPHeaders, carrier)

		// Создаем новый span
		operationName := fmt.Sprintf("HTTP %s %s", c.Request.Method, c.FullPath())
		span := tracer.StartSpan(
			operationName,
			ext.RPCServerOption(spanCtx),
		)
		defer span.Finish()

		// Добавляем стандартные теги
		ext.HTTPMethod.Set(span, c.Request.Method)
		ext.HTTPUrl.Set(span, c.Request.URL.String())
		ext.Component.Set(span, "gin")

		// Добавляем request ID если есть
		if requestID, exists := c.Get(requestIDKey); exists {
			span.SetTag("request.id", requestID)
		}

		// Добавляем span в контекст
		ctx := opentracing.ContextWithSpan(c.Request.Context(), span)
		c.Request = c.Request.WithContext(ctx)

		c.Next()

		// Устанавливаем статус после обработки
		ext.HTTPStatusCode.Set(span, uint16(c.Writer.Status()))
		if c.Writer.Status() >= 500 {
			ext.Error.Set(span, true)
			// Добавляем ошибки если есть
			if len(c.Errors) > 0 {
				span.SetTag("error.message", c.Errors.String())
			}
		}
	}
}

// GinRateLimiterMiddleware создает Gin middleware для ограничения частоты запросов
func GinRateLimiterMiddleware(rps int, burst int) gin.HandlerFunc {
	// Глобальный rate limiter
	globalLimiter := rate.NewLimiter(rate.Limit(rps), burst)

	// Map для хранения лимитеров по IP
	ipLimiters := make(map[string]*rate.Limiter)
	var mu sync.Mutex

	return func(c *gin.Context) {
		// Глобальное ограничение
		if !globalLimiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many requests. Please try again later.",
			})
			return
		}

		// Ограничение по IP
		ip := c.ClientIP()
		mu.Lock()
		limiter, exists := ipLimiters[ip]
		if !exists {
			// Создаем лимитер с более низким лимитом для отдельных IP
			limiter = rate.NewLimiter(rate.Limit(rps/10), burst/10)
			ipLimiters[ip] = limiter
		}
		mu.Unlock()

		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many requests from your IP. Please try again later.",
			})
			return
		}

		c.Next()
	}
}

// GinRecoveryMiddleware создает Gin middleware для обработки паник с логированием
func GinRecoveryMiddleware(logger Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Получаем стек вызовов
				stack := debug.Stack()

				// Получаем логгер из контекста
				ctxLogger := LoggerFromContext(c.Request.Context())

				// Логируем панику
				ctxLogger.WithFields(map[string]interface{}{
					"error":  err,
					"stack":  string(stack),
					"path":   c.Request.URL.Path,
					"method": c.Request.Method,
				}).Error("Panic recovered")

				// Отправляем ошибку клиенту
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error":      "Internal Server Error",
					"request_id": c.GetString(requestIDKey), // Добавляем request ID для отладки
				})
			}
		}()
		c.Next()
	}
}

// GinCORSMiddleware создает Gin middleware для CORS
func GinCORSMiddleware(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Проверяем, разрешен ли origin
		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-Request-ID")
			c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")
			c.Header("Access-Control-Max-Age", "86400") // 24 часа
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// GinSecurityHeaders добавляет security заголовки
func GinSecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Защита от XSS
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")

		// Защита от clickjacking
		c.Header("X-Frame-Options", "DENY")

		// Принудительное использование HTTPS
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		// Контент Security Policy
		c.Header("Content-Security-Policy", "default-src 'self'")

		// Referrer Policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Feature Policy
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		c.Next()
	}
}

// GinRequestSizeLimit ограничивает размер тела запроса
func GinRequestSizeLimit(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		var w http.ResponseWriter = c.Writer
		c.Request.Body = http.MaxBytesReader(w, c.Request.Body, limit)

		c.Next()

		// Проверяем, была ли ошибка размера
		if c.IsAborted() && c.Writer.Status() == http.StatusRequestEntityTooLarge {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": fmt.Sprintf("Request body too large. Maximum allowed size is %d bytes", limit),
			})
		}
	}
}

// GinBodyLoggerMiddleware создает Gin middleware для логирования тела запроса/ответа (только для отладки)
func GinBodyLoggerMiddleware(logger Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Не логируем для multipart (загрузка файлов)
		if strings.Contains(c.GetHeader("Content-Type"), "multipart/form-data") {
			c.Next()
			return
		}

		// Читаем тело запроса
		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(c.Request.Body)
			// Восстанавливаем тело запроса
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// Создаем custom writer для перехвата ответа
		blw := &bodyLogWriter{
			body:           bytes.NewBufferString(""),
			ResponseWriter: c.Writer,
		}
		c.Writer = blw

		// Обрабатываем запрос
		c.Next()

		// Логируем только для отладки и небольших тел
		if len(bodyBytes) < 1024 && blw.body.Len() < 1024 {
			ctxLogger := LoggerFromContext(c.Request.Context())
			ctxLogger.WithFields(map[string]interface{}{
				"request_body":  string(bodyBytes),
				"response_body": blw.body.String(),
				"status":        c.Writer.Status(),
			}).Debug("Request/Response bodies")
		}
	}
}

type bodyLogWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w bodyLogWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}
