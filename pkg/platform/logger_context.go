package platform

import (
	"context"
)

// contextKey тип для ключей контекста
type contextKey string

const (
	// loggerKey ключ для хранения логгера в контексте
	loggerKey contextKey = "logger"
)

// LoggerFromContext извлекает логгер из контекста
// Если логгер не найден, возвращает дефолтный логгер
func LoggerFromContext(ctx context.Context) *Logger {
	if logger, ok := ctx.Value(loggerKey).(*Logger); ok {
		return logger
	}
	// Возвращаем дефолтный логгер если не найден в контексте
	return NewLogger("default")
}

// ContextWithLogger добавляет логгер в контекст
func ContextWithLogger(ctx context.Context, logger *Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// WithContext создает новый контекст с логгером
func WithContext(ctx context.Context) context.Context {
	logger := LoggerFromContext(ctx)
	return ContextWithLogger(ctx, logger)
}
