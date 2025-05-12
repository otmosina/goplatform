package platform

import (
	"context"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// zerologLogger реализация Logger с использованием zerolog
type Logger struct {
	logger zerolog.Logger
}

// NewLogger создает новый логгер с использованием zerolog
func NewLogger(serviceName string) *Logger {
	// Настраиваем красивый вывод для разработки
	output := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: "15:04:05",
	}

	logger := zerolog.New(output).
		With().
		Timestamp().
		Str("service", serviceName).
		Logger()

	// Устанавливаем глобальный логгер
	log.Logger = logger

	return &Logger{
		logger: logger,
	}
}

// NewProductionLogger создает production логгер (JSON формат)
func NewProductionLogger(serviceName string) *Logger {
	logger := zerolog.New(os.Stdout).
		With().
		Timestamp().
		Str("service", serviceName).
		Logger()

	return &Logger{
		logger: logger,
	}
}

func (l *Logger) Debug(msg string, args ...interface{}) {
	event := l.logger.Debug()
	l.addFields(event, args...).Msg(msg)
}

func (l *Logger) Info(msg string, args ...interface{}) {
	event := l.logger.Info()
	l.addFields(event, args...).Msg(msg)
}

func (l *Logger) Warn(msg string, args ...interface{}) {
	event := l.logger.Warn()
	l.addFields(event, args...).Msg(msg)
}

func (l *Logger) Error(msg string, args ...interface{}) {
	event := l.logger.Error()
	l.addFields(event, args...).Msg(msg)
}

// addFields добавляет поля в событие логгера
func (l *Logger) addFields(event *zerolog.Event, args ...interface{}) *zerolog.Event {
	if len(args)%2 != 0 {
		event.Interface("malformed_fields", args)
		return event
	}

	for i := 0; i < len(args); i += 2 {
		key, ok := args[i].(string)
		if !ok {
			continue
		}

		switch value := args[i+1].(type) {
		case string:
			event.Str(key, value)
		case int:
			event.Int(key, value)
		case int64:
			event.Int64(key, value)
		case uint:
			event.Uint(key, value)
		case uint64:
			event.Uint64(key, value)
		case float64:
			event.Float64(key, value)
		case bool:
			event.Bool(key, value)
		case error:
			event.Err(value)
		default:
			event.Interface(key, value)
		}
	}

	return event
}

// WithContext создает логгер с контекстом
func (l *Logger) WithContext(ctx context.Context) *Logger {
	return &Logger{
		logger: l.logger.With().Ctx(ctx).Logger(),
	}
}

// WithFields создает логгер с дополнительными полями
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	loggerContext := l.logger.With()
	for key, value := range fields {
		loggerContext = loggerContext.Interface(key, value)
	}
	return &Logger{
		logger: loggerContext.Logger(),
	}
}

// ToContext добавляет логгер в контекст
func (l *Logger) ToContext(ctx context.Context) context.Context {
	return ContextWithLogger(ctx, l)
}

// FromContext создает новый логгер из контекста
func FromContext(ctx context.Context) *Logger {
	return LoggerFromContext(ctx)
}
