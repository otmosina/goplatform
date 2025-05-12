package platform

import (
	"context"

	"github.com/gin-gonic/gin"
)

// ServiceHandler интерфейс для регистрации HTTP роутов
type ServiceHandler interface {
	RegisterRoutes(router *gin.Engine) error
}

// Logger интерфейс для логирования
type LoggerI interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	WithContext(ctx context.Context) Logger
	WithFields(fields map[string]any) Logger
	ToContext(ctx context.Context) context.Context
	FromContext(ctx context.Context) Logger
}
