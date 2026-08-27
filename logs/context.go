package logs

import (
	"context"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type contextKey string

const contextKeyLogger contextKey = "jxone-logger"

type contextState struct {
	logger *zap.SugaredLogger
	fields []interface{}
}

// WithContextFields 返回附加指定键值字段的新上下文。
func WithContextFields(ctx context.Context, fields ...interface{}) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	state := contextStateFromContext(ctx)
	state.fields = append(append([]interface{}{}, state.fields...), fields...)
	return context.WithValue(ctx, contextKeyLogger, &state)
}

// WithContextLogger 返回使用指定日志器的新上下文，并保留已有日志字段。
func WithContextLogger(ctx context.Context, l *zap.SugaredLogger) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	state := contextStateFromContext(ctx)
	if l == nil {
		l = Get("default")
	}
	state.logger = l
	return context.WithValue(ctx, contextKeyLogger, &state)
}

// SetContextFields 向 Gin 上下文追加日志字段。
// 标准上下文不可变，应使用 WithContextFields。
func SetContextFields(ctx context.Context, fields ...interface{}) {
	gctx, ok := ctx.(*gin.Context)
	if !ok || gctx == nil {
		return
	}
	state := contextStateFromContext(gctx)
	state.fields = append(append([]interface{}{}, state.fields...), fields...)
	gctx.Set(string(contextKeyLogger), &state)
}

// SetContextLogger 设置 Gin 上下文的日志器。
// 标准上下文不可变，应使用 WithContextLogger。
func SetContextLogger(ctx context.Context, l *zap.SugaredLogger) {
	gctx, ok := ctx.(*gin.Context)
	if !ok || gctx == nil {
		return
	}
	state := contextStateFromContext(gctx)
	if l == nil {
		l = Get("default")
	}
	state.logger = l
	gctx.Set(string(contextKeyLogger), &state)
}

// LoggerFromContext 获取上下文日志器；未设置时返回当前默认日志器。
func LoggerFromContext(ctx context.Context) *zap.SugaredLogger {
	return loggerForContext(ctx, Get("default"))
}

func loggerForContext(ctx context.Context, fallback *zap.SugaredLogger) *zap.SugaredLogger {
	state := contextStateFromContext(ctx)
	l := state.logger
	if l == nil {
		l = fallback
	}
	if l == nil {
		l = Get("default")
	}
	if len(state.fields) != 0 {
		l = l.With(state.fields...)
	}
	return l
}

func contextStateFromContext(ctx context.Context) contextState {
	if ctx == nil {
		return contextState{}
	}
	if gctx, ok := ctx.(*gin.Context); ok && gctx != nil {
		if value, exists := gctx.Get(string(contextKeyLogger)); exists {
			return contextStateFromValue(value)
		}
	}
	return contextStateFromValue(ctx.Value(contextKeyLogger))
}

func contextStateFromValue(value interface{}) contextState {
	switch value := value.(type) {
	case *contextState:
		if value != nil {
			return *value
		}
	case contextState:
		return value
	case *zap.SugaredLogger:
		return contextState{logger: value}
	}
	return contextState{}
}

func DebugContext(ctx context.Context, args ...interface{}) {
	callerLogger(LoggerFromContext(ctx)).Debug(args...)
}
func InfoContext(ctx context.Context, args ...interface{}) {
	callerLogger(LoggerFromContext(ctx)).Info(args...)
}
func WarnContext(ctx context.Context, args ...interface{}) {
	callerLogger(LoggerFromContext(ctx)).Warn(args...)
}
func ErrorContext(ctx context.Context, args ...interface{}) {
	callerLogger(LoggerFromContext(ctx)).Error(args...)
}
func FatalContext(ctx context.Context, args ...interface{}) {
	callerLogger(LoggerFromContext(ctx)).Fatal(args...)
}

func DebugContextf(ctx context.Context, template string, args ...interface{}) {
	callerLogger(LoggerFromContext(ctx)).Debugf(template, args...)
}
func InfoContextf(ctx context.Context, template string, args ...interface{}) {
	callerLogger(LoggerFromContext(ctx)).Infof(template, args...)
}
func WarnContextf(ctx context.Context, template string, args ...interface{}) {
	callerLogger(LoggerFromContext(ctx)).Warnf(template, args...)
}
func ErrorContextf(ctx context.Context, template string, args ...interface{}) {
	callerLogger(LoggerFromContext(ctx)).Errorf(template, args...)
}
func FatalContextf(ctx context.Context, template string, args ...interface{}) {
	callerLogger(LoggerFromContext(ctx)).Fatalf(template, args...)
}

func DebugContextw(ctx context.Context, msg string, keysAndValues ...interface{}) {
	callerLogger(LoggerFromContext(ctx)).Debugw(msg, keysAndValues...)
}
func InfoContextw(ctx context.Context, msg string, keysAndValues ...interface{}) {
	callerLogger(LoggerFromContext(ctx)).Infow(msg, keysAndValues...)
}
func WarnContextw(ctx context.Context, msg string, keysAndValues ...interface{}) {
	callerLogger(LoggerFromContext(ctx)).Warnw(msg, keysAndValues...)
}
func ErrorContextw(ctx context.Context, msg string, keysAndValues ...interface{}) {
	callerLogger(LoggerFromContext(ctx)).Errorw(msg, keysAndValues...)
}
func FatalContextw(ctx context.Context, msg string, keysAndValues ...interface{}) {
	callerLogger(LoggerFromContext(ctx)).Fatalw(msg, keysAndValues...)
}
