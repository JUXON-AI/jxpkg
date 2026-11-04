package logtobff

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/JUXON-AI/jxpkg/requestid"
	"github.com/redis/go-redis/v9"
)

// sessionRedisError 保存失败时的有界诊断快照，原始原因只用于错误匹配，不写日志。
type sessionRedisError struct {
	cause     error
	operation string
	elapsed   time.Duration
	pool      redis.PoolStats
}

// Error 只返回固定安全文本，避免上层误格式化时泄漏 Redis key 或地址。
func (*sessionRedisError) Error() string { return "authentication Redis operation failed" }

// Unwrap 保留调用方对取消、超时和 Redis 哨兵错误的匹配。
func (e *sessionRedisError) Unwrap() error { return e.cause }

// redisFailure 只包装失败，不在传播层记录日志，也不增加 Redis 请求。
func (s *store) redisFailure(operation string, started time.Time, cause error) error {
	return &sessionRedisError{cause: cause, operation: operation, elapsed: time.Since(started), pool: *s.db.PoolStats()}
}

// sessionDiagnosticContext 只携带关联 ID，不继承请求上下文中可能含密钥的日志字段。
func sessionDiagnosticContext(ctx context.Context) context.Context {
	return logs.WithContextFields(context.Background(), "request_id", requestid.FromContext(ctx))
}

// sessionFailureFields 用类型和固定枚举区分故障，不读取命令、参数或上游错误文本。
func sessionFailureFields(err error) []any {
	kind, operation := "unknown", ""
	var network *net.OpError
	if errors.As(err, &network) {
		switch network.Op {
		case "dial", "read", "write":
			operation = network.Op
		default:
			operation = "other"
		}
	}
	var (
		networkError net.Error
		serverError  redis.Error
	)
	switch {
	case errors.Is(err, context.Canceled):
		kind = "context_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		kind = "context_deadline"
	case errors.Is(err, redis.ErrPoolTimeout):
		kind = "pool_timeout"
	case errors.Is(err, redis.ErrPoolExhausted):
		kind = "pool_exhausted"
	case errors.Is(err, syscall.ECONNREFUSED):
		kind = "connection_refused"
	case errors.Is(err, syscall.ECONNRESET):
		kind = "connection_reset"
	case errors.As(err, &networkError) && networkError.Timeout():
		kind = "network_timeout"
	case errors.As(err, &networkError):
		kind = "network_error"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		kind = "connection_closed"
	case errors.As(err, &serverError):
		kind = "redis_server_error"
	case errors.Is(err, _errMissing):
		kind = "session_missing"
	case errors.Is(err, _errBusy):
		kind = "session_busy"
	case errors.Is(err, _errInvalid):
		kind = "session_invalid"
	}
	fields := []any{"failure_kind", kind, "network_operation", operation}
	var failure *sessionRedisError
	if errors.As(err, &failure) {
		fields = append(fields,
			"dependency", "redis", "redis_operation", failure.operation,
			"elapsed_ms", failure.elapsed.Milliseconds(),
			"pool_total_conns", failure.pool.TotalConns,
			"pool_idle_conns", failure.pool.IdleConns,
			"pool_timeouts_total", failure.pool.Timeouts,
			"pool_wait_count_total", failure.pool.WaitCount,
		)
	}
	return fields
}
