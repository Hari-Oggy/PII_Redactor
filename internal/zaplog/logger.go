// Package zaplog provides a global structured logger using go.uber.org/zap.
// It is initialized once from the config and can be accessed from anywhere
// via zaplog.L() (logger) and zaplog.S() (sugared logger).
package zaplog

import (
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	logger     *zap.Logger
	sugar      *zap.SugaredLogger
	initOnce   sync.Once
)

// Init initializes the global zap logger from config values.
// level: "debug", "info", "warn", "error"
// format: "json" or "console"
func Init(level, format string) {
	initOnce.Do(func() {
		var cfg zap.Config

		if format == "console" {
			cfg = zap.NewDevelopmentConfig()
			cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		} else {
			cfg = zap.NewProductionConfig()
		}

		// Parse log level.
		var zapLevel zapcore.Level
		switch level {
		case "debug":
			zapLevel = zapcore.DebugLevel
		case "warn":
			zapLevel = zapcore.WarnLevel
		case "error":
			zapLevel = zapcore.ErrorLevel
		default:
			zapLevel = zapcore.InfoLevel
		}
		cfg.Level = zap.NewAtomicLevelAt(zapLevel)

		var err error
		logger, err = cfg.Build(
			zap.AddCallerSkip(1), // skip the wrapper function
		)
		if err != nil {
			// Fallback to nop logger — should never happen.
			logger = zap.NewNop()
		}
		sugar = logger.Sugar()
	})
}

// L returns the global zap.Logger. Must call Init() first.
func L() *zap.Logger {
	if logger == nil {
		Init("info", "json")
	}
	return logger
}

// S returns the global sugared logger. Must call Init() first.
func S() *zap.SugaredLogger {
	if sugar == nil {
		Init("info", "json")
	}
	return sugar
}

// Sync flushes any buffered log entries. Call before process exit.
func Sync() {
	if logger != nil {
		_ = logger.Sync()
	}
}

// With returns a new logger with the given fields.
func With(fields ...zap.Field) *zap.Logger {
	return L().With(fields...)
}
