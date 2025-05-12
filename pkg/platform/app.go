package platform

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// App представляет основную структуру приложения
type App struct {
	config      *Config
	httpServer  *http.Server
	probeServer *http.Server
	shutdownWG  sync.WaitGroup
	logger      *Logger
}

// Config содержит конфигурацию приложения
type Config struct {
	ServiceName string
	Version     string
	HTTPPort    int
	ProbePort   int
	Environment string // "development" или "production"

	// Middleware options
	EnableLogging     bool
	EnableMetrics     bool
	EnableTracing     bool
	EnableRateLimiter bool

	// Server options
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration

	// Custom middleware
	GinMiddleware []gin.HandlerFunc

	// CORS settings
	EnableCORS     bool
	AllowedOrigins []string
}

// Option представляет функцию для настройки конфигурации
type Option func(*Config)

// DefaultConfig возвращает конфигурацию по умолчанию
func DefaultConfig() *Config {
	return &Config{
		ServiceName:       "service",
		Version:           "1.0.0",
		HTTPPort:          8080,
		ProbePort:         8081,
		Environment:       "development",
		EnableLogging:     true,
		EnableMetrics:     true,
		EnableTracing:     false,
		EnableRateLimiter: false,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ShutdownTimeout:   30 * time.Second,
		EnableCORS:        false,
		AllowedOrigins:    []string{"*"},
	}
}

// WithServiceName устанавливает имя сервиса
func WithServiceName(name string) Option {
	return func(c *Config) {
		c.ServiceName = name
	}
}

// WithHTTPPort устанавливает порт для HTTP
func WithHTTPPort(port int) Option {
	return func(c *Config) {
		c.HTTPPort = port
	}
}

// WithProbePort устанавливает порт для health checks
func WithProbePort(port int) Option {
	return func(c *Config) {
		c.ProbePort = port
	}
}

// WithEnvironment устанавливает окружение (development/production)
func WithEnvironment(env string) Option {
	return func(c *Config) {
		c.Environment = env
	}
}

// WithLogging включает/выключает логирование
func WithLogging(enabled bool) Option {
	return func(c *Config) {
		c.EnableLogging = enabled
	}
}

// WithMetrics включает/выключает метрики
func WithMetrics(enabled bool) Option {
	return func(c *Config) {
		c.EnableMetrics = enabled
	}
}

// WithTracing включает/выключает трейсинг
func WithTracing(enabled bool) Option {
	return func(c *Config) {
		c.EnableTracing = enabled
	}
}

// WithRateLimiter включает/выключает rate limiting
func WithRateLimiter(enabled bool) Option {
	return func(c *Config) {
		c.EnableRateLimiter = enabled
	}
}

// WithShutdownTimeout устанавливает таймаут для graceful shutdown
func WithShutdownTimeout(timeout time.Duration) Option {
	return func(c *Config) {
		c.ShutdownTimeout = timeout
	}
}

// WithGinMiddleware добавляет кастомные Gin middleware
func WithGinMiddleware(middleware ...gin.HandlerFunc) Option {
	return func(c *Config) {
		c.GinMiddleware = append(c.GinMiddleware, middleware...)
	}
}

// WithCORS включает CORS с указанными origins
func WithCORS(origins ...string) Option {
	return func(c *Config) {
		c.EnableCORS = true
		if len(origins) > 0 {
			c.AllowedOrigins = origins
		}
	}
}

func NewApp(ctx context.Context, opts ...Option) (*App, error) {
	config := DefaultConfig()
	for _, opt := range opts {
		opt(config)
	}

	// выбираем логгер в зависимости от окружения

	var logger *Logger
	if config.Environment == "production" {
		logger = NewProductionLogger(config.ServiceName)
	} else {
		logger = NewLogger(config.ServiceName)
	}

	return &App{
		config: config,
		logger: logger,
	}, nil
}

// Logger возвращает логгер
func (a *App) Logger() *Logger {
	return a.logger
}

// Config возвращает конфигурацию
func (a *App) Config() *Config {
	return a.config
}

func (app *App) RegisterRoutes(ctx context.Context, handler ServiceHandler) error {

	if app.config.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// базовые middleware
	router.Use(GinRequestID())
	router.Use(GinRecoveryMiddleware(*app.logger))

	if app.config.EnableMetrics {
		router.Use(GinMetricsMiddleware())
	}

	if app.config.EnableTracing {
		router.Use(GinTracingMiddleware())
	}

	// TODO реализовать rate limiter
	if app.config.EnableRateLimiter {
		router.Use(GinRateLimiterMiddleware(100, 200))
	}

	if app.config.EnableCORS {
		router.Use(GinCORSMiddleware(app.config.AllowedOrigins))
	}

	// security middleware
	router.Use(GinSecurityHeaders())

	// Ограничиваем размер запроса (10MB)
	router.Use(GinRequestSizeLimit(10 << 20))

	// Добавляем кастомные middleware
	for _, middleware := range app.config.GinMiddleware {
		router.Use(middleware)
	}

	// регистрируем роуты
	if err := handler.RegisterRoutes(router); err != nil {
		return fmt.Errorf("failed to register routes: %w", err)
	}

	app.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", app.config.HTTPPort),
		Handler:      router,
		ReadTimeout:  app.config.ReadTimeout,
		WriteTimeout: app.config.WriteTimeout,
		IdleTimeout:  app.config.IdleTimeout,
	}
	return nil
}

func (app *App) Run(ctx context.Context) error {
	if app.httpServer == nil {
		return fmt.Errorf("http server not initialized")
	}

	app.shutdownWG.Add(1)
	go func() {
		defer app.shutdownWG.Done()
		app.logger.Info("Starting HTTP server", "port", app.config.HTTPPort)
		if err := app.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			app.logger.Error("failed to start http server", "error", err)
		}
	}()

	// запускаем probe server
	app.startProbeServer()

	// ожидаем сигнал для завершения
	app.waitForShutdown(ctx)

	// выполняем graceful shutdown
	return app.shutdown(ctx)
}

// startProbeServer запускает сервер для health checks
func (app *App) startProbeServer() {
	probeRouter := gin.New()
	probeRouter.Use(gin.Recovery())

	// Liveness probe
	probeRouter.GET("/liveness", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "alive"})
	})

	// Readiness probe
	probeRouter.GET("/readiness", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	// Metrics endpoint
	if app.config.EnableMetrics {
		probeRouter.GET("/metrics", gin.WrapH(promhttp.Handler()))
	}

	// Info endpoint
	probeRouter.GET("/info", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service": app.config.ServiceName,
			"version": app.config.Version,
		})
	})

	app.probeServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", app.config.ProbePort),
		Handler: probeRouter,
	}

	//TODO::: app.shutdownWG.Add(1)
	go func() {
		defer app.shutdownWG.Done()
		app.logger.Info("Starting probe server", "port", app.config.ProbePort)
		if err := app.probeServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			app.logger.Error("Probe server error", "error", err)
		}
	}()
}

// waitForShutdown ожидает сигнал для завершения
func (app *App) waitForShutdown(ctx context.Context) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-ctx.Done():
	case sig := <-quit:
		app.logger.Info("Received shutdown signal", "signal", sig)
	}
}

// shutdown выполняет graceful shutdown
func (app *App) shutdown(ctx context.Context) error {
	shutdownCtx, cancel := context.WithTimeout(ctx, app.config.ShutdownTimeout)
	defer cancel()

	app.logger.Info("Starting graceful shutdown")

	// Останавливаем HTTP сервер
	if app.httpServer != nil {
		if err := app.httpServer.Shutdown(shutdownCtx); err != nil {
			app.logger.Error("Failed to shutdown HTTP server", "error", err)
		}
	}

	// Останавливаем probe сервер
	if app.probeServer != nil {
		if err := app.probeServer.Shutdown(shutdownCtx); err != nil {
			app.logger.Error("Failed to shutdown probe server", "error", err)
		}
	}

	// Ждем завершения всех горутин
	app.shutdownWG.Wait()
	app.logger.Info("Application shutdown complete")

	return nil
}
