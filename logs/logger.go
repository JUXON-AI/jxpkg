package logs

import (
	"context"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type contextKey string

const (
	contextKeyLogger    contextKey = "goar-logger"
	contextKeyRequestID contextKey = "reqid"
)

var logger *zap.SugaredLogger

// With 返回带附加字段的 logger。
func With(args ...interface{}) *zap.SugaredLogger { return logger.With(args...) }

// Sync 刷新缓冲日志，确保所有日志都已写出。
func Sync() error                                   { return logger.Sync() }

func Debug(args ...interface{})  { logger.Debug(args...) }
func Info(args ...interface{})   { logger.Info(args...) }
func Warn(args ...interface{})   { logger.Warn(args...) }
func Error(args ...interface{})  { logger.Error(args...) }
func Fatal(args ...interface{})  { logger.Fatal(args...) }

func Debugf(template string, args ...interface{}) { logger.Debugf(template, args...) }
func Infof(template string, args ...interface{})  { logger.Infof(template, args...) }
func Warnf(template string, args ...interface{})  { logger.Warnf(template, args...) }
func Errorf(template string, args ...interface{}) { logger.Errorf(template, args...) }
func Fatalf(template string, args ...interface{}) { logger.Fatalf(template, args...) }

func Debugw(msg string, keysAndValues ...interface{}) { logger.Debugw(msg, keysAndValues...) }
func Infow(msg string, keysAndValues ...interface{})  { logger.Infow(msg, keysAndValues...) }
func Warnw(msg string, keysAndValues ...interface{})  { logger.Warnw(msg, keysAndValues...) }
func Errorw(msg string, keysAndValues ...interface{}) { logger.Errorw(msg, keysAndValues...) }
func Fatalw(msg string, keysAndValues ...interface{}) { logger.Fatalw(msg, keysAndValues...) }

func DebugContext(ctx context.Context, args ...interface{}) { LoggerFromContext(ctx).Debug(args...) }
func InfoContext(ctx context.Context, args ...interface{})  { LoggerFromContext(ctx).Info(args...) }
func WarnContext(ctx context.Context, args ...interface{})  { LoggerFromContext(ctx).Warn(args...) }
func ErrorContext(ctx context.Context, args ...interface{}) { LoggerFromContext(ctx).Error(args...) }
func FatalContext(ctx context.Context, args ...interface{}) { LoggerFromContext(ctx).Fatal(args...) }

func DebugContextf(ctx context.Context, template string, args ...interface{}) {
	LoggerFromContext(ctx).Debugf(template, args...)
}
func InfoContextf(ctx context.Context, template string, args ...interface{}) {
	LoggerFromContext(ctx).Infof(template, args...)
}
func WarnContextf(ctx context.Context, template string, args ...interface{}) {
	LoggerFromContext(ctx).Warnf(template, args...)
}
func ErrorContextf(ctx context.Context, template string, args ...interface{}) {
	LoggerFromContext(ctx).Errorf(template, args...)
}
func FatalContextf(ctx context.Context, template string, args ...interface{}) {
	LoggerFromContext(ctx).Fatalf(template, args...)
}

func DebugContextw(ctx context.Context, msg string, keysAndValues ...interface{}) {
	LoggerFromContext(ctx).Debugw(msg, keysAndValues...)
}
func InfoContextw(ctx context.Context, msg string, keysAndValues ...interface{}) {
	LoggerFromContext(ctx).Infow(msg, keysAndValues...)
}
func WarnContextw(ctx context.Context, msg string, keysAndValues ...interface{}) {
	LoggerFromContext(ctx).Warnw(msg, keysAndValues...)
}
func ErrorContextw(ctx context.Context, msg string, keysAndValues ...interface{}) {
	LoggerFromContext(ctx).Errorw(msg, keysAndValues...)
}
func FatalContextw(ctx context.Context, msg string, keysAndValues ...interface{}) {
	LoggerFromContext(ctx).Fatalw(msg, keysAndValues...)
}

// WithContextFields 向 context 写入带附加字段的 logger，供后续 LoggerFromContext 使用。
func WithContextFields(ctx context.Context, fields ...interface{}) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	l := logger
	val := ctx.Value(contextKeyLogger)
	if val != nil {
		var ok bool
		l, ok = val.(*zap.SugaredLogger)
		if !ok {
			l = logger
		}
	}
	l = l.With(fields...)
	return context.WithValue(ctx, contextKeyLogger, l)
}

// WithContextLogger 将指定 logger 存入 context。
func WithContextLogger(ctx context.Context, l *zap.SugaredLogger) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, contextKeyLogger, l)
}

// SetContextFields 向 context 中的 logger 附加字段（也支持 *gin.Context）。
func SetContextFields(ctx context.Context, fields ...interface{}) {
	if gctx, ok := ctx.(*gin.Context); ok {
		l := LoggerFromContext(ctx)
		l = l.With(fields...)
		gctx.Set(string(contextKeyLogger), l)
		return
	}
	ctx = WithContextFields(ctx, fields...)
}

// SetContextLogger 将指定 logger 存入 context（也支持 *gin.Context）。
func SetContextLogger(ctx context.Context, l *zap.SugaredLogger) {
	if gctx, ok := ctx.(*gin.Context); ok {
		gctx.Set(string(contextKeyLogger), l)
		return
	}
	ctx = WithContextLogger(ctx, l)
}

// LoggerFromContext 从 context 中提取 logger，未设置时返回全局默认 logger。
func LoggerFromContext(ctx context.Context) *zap.SugaredLogger {
	if ctx == nil {
		return logger
	}
	if gctx, ok := ctx.(*gin.Context); ok {
		val, ok := gctx.Get(string(contextKeyLogger))
		if !ok {
			return logger
		}
		l, ok := val.(*zap.SugaredLogger)
		if !ok {
			return logger
		}
		return l
	}
	val := ctx.Value(contextKeyLogger)
	if val == nil {
		return logger
	}
	l, ok := val.(*zap.SugaredLogger)
	if !ok {
		return logger
	}
	return l
}