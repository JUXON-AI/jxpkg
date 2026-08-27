package logs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

const defaultSlowThreshold = 200 * time.Millisecond

// GetGorm 返回实现 GORM logger.Interface 的日志器。
func GetGorm(name string) gormlogger.Interface {
	return &gormLogger{
		logger:        Get(name),
		level:         gormlogger.Info,
		slowThreshold: defaultSlowThreshold,
	}
}

var _ gormlogger.Interface = (*gormLogger)(nil)
var _ gorm.ParamsFilter = (*gormLogger)(nil)

type gormLogger struct {
	logger                    *zap.SugaredLogger
	level                     gormlogger.LogLevel
	slowThreshold             time.Duration
	ignoreRecordNotFoundError bool
}

// ParamsFilter 保留 SQL 占位符，避免参数中的密码和令牌进入日志。
func (g *gormLogger) ParamsFilter(_ context.Context, sql string, _ ...interface{}) (string, []interface{}) {
	return sql, nil
}

func (g *gormLogger) LogMode(level gormlogger.LogLevel) gormlogger.Interface {
	clone := *g
	clone.level = level
	return &clone
}

func (g *gormLogger) Info(ctx context.Context, msg string, data ...interface{}) {
	if g.level >= gormlogger.Info {
		g.contextLogger(ctx).Infof(msg, data...)
	}
}

func (g *gormLogger) Warn(ctx context.Context, msg string, data ...interface{}) {
	if g.level >= gormlogger.Warn {
		g.contextLogger(ctx).Warnf(msg, data...)
	}
}

func (g *gormLogger) Error(ctx context.Context, msg string, data ...interface{}) {
	if g.level >= gormlogger.Error {
		g.contextLogger(ctx).Errorf(msg, data...)
	}
}

func (g *gormLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	if g.level == gormlogger.Silent {
		return
	}

	elapsed := time.Since(begin)
	sql, rows := fc()
	fields := []interface{}{
		"elapsed", fmt.Sprintf("%.3fms", float64(elapsed.Nanoseconds())/1e6),
		"rows", rows,
	}
	l := g.contextLogger(ctx)

	switch {
	case err != nil && g.level >= gormlogger.Error &&
		(!g.ignoreRecordNotFoundError || !errors.Is(err, gorm.ErrRecordNotFound)):
		l.Errorw(sql, append(fields, "error", err)...)
	case g.slowThreshold > 0 && elapsed > g.slowThreshold && g.level >= gormlogger.Warn:
		l.Warnw(sql, append(fields, "slow", true)...)
	case g.level >= gormlogger.Info:
		l.Infow(sql, fields...)
	}
}

func (g *gormLogger) contextLogger(ctx context.Context) *zap.SugaredLogger {
	return loggerForContext(ctx, g.logger).
		Desugar().
		WithOptions(zap.AddCallerSkip(2)).
		Sugar()
}
