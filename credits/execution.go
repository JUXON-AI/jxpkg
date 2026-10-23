package credits

import (
	"context"
	"errors"
	"sync"

	"github.com/JUXON-AI/jxpkg/safeerror"
)

// ExecutionContextKey 用于标准 Context 与 HTTP 框架之间传递同一个执行对象。
// 该值必须由服务端代码设置，不允许从请求字段或 Header 导入。
const ExecutionContextKey = "jxpkg.credits.execution"

// AcquireFunc 是已授权员工的连接领取函数；可在业务入口补充任务身份检查。
type AcquireFunc func(context.Context, Subject) (Connection, error)

// Execution 在一次执行内领取并复用连接，不持有应用配置或全局员工缓存。
// 领取失败也固定到本次执行；显式重新执行时创建新的 Execution。
type Execution struct {
	subject    Subject
	acquire    AcquireFunc
	mu         sync.Mutex
	started    bool
	done       chan struct{}
	connection Connection
	err        error
}

// NewExecution 接收业务已验证的员工身份和领取能力，不自行选择员工或执行授权。
func NewExecution(subject Subject, acquire AcquireFunc) (*Execution, error) {
	if err := subject.Validate(); err != nil {
		return nil, ErrDenied
	}
	if acquire == nil {
		return nil, ErrUnavailable
	}
	return &Execution{subject: subject, acquire: acquire, done: make(chan struct{})}, nil
}

// Subject 返回不可变员工作用域，供业务层核对资源归属。
func (e *Execution) Subject() Subject {
	if e == nil {
		return Subject{}
	}
	return e.subject
}

// AcquireDefault 在本次执行中至多领取一次，独立等待者可被自己的 Context 取消。
func (e *Execution) AcquireDefault(ctx context.Context) (Connection, error) {
	if e == nil || e.acquire == nil || e.done == nil || ctx == nil {
		return Connection{}, ErrDenied
	}
	if err := ctx.Err(); err != nil {
		return Connection{}, err
	}
	e.mu.Lock()
	first := !e.started
	e.started = true
	e.mu.Unlock()
	if first {
		func() {
			defer close(e.done)
			// 业务回调发生 panic 时仍释放其他等待者；panic 由应用的执行边界处理。
			e.err = ErrUnavailable
			connection, err := e.acquire(ctx, e.subject)
			if err == nil {
				err = ValidateConnection(connection)
			}
			if ctx.Err() != nil {
				err = errors.Join(ctx.Err(), err)
			}
			if err != nil {
				connection = Connection{}
				var classification error
				switch {
				case errors.Is(err, ErrDenied):
					classification = ErrDenied
				case errors.Is(err, context.Canceled):
					classification = context.Canceled
				case errors.Is(err, context.DeadlineExceeded):
					classification = context.DeadlineExceeded
				default:
					classification = ErrUnavailable
				}
				err = safeerror.Wrap(classification.Error(), errors.Join(classification, err))
			}
			e.connection, e.err = connection, err
		}()
	}
	select {
	case <-ctx.Done():
		return Connection{}, ctx.Err()
	case <-e.done:
		if err := ctx.Err(); err != nil {
			return Connection{}, err
		}
		return e.connection, e.err
	}
}

// WithExecution 将执行对象传递给下游，不读取配置、身份字段或网络。
func WithExecution(ctx context.Context, e *Execution) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, ExecutionContextKey, e)
}

// ExecutionFromContext 读取入口显式绑定的执行对象；缺失时拒绝领取。
func ExecutionFromContext(ctx context.Context) (*Execution, error) {
	if ctx == nil {
		return nil, ErrDenied
	}
	e, ok := ctx.Value(ExecutionContextKey).(*Execution)
	if !ok || e == nil || e.acquire == nil {
		return nil, ErrDenied
	}
	return e, nil
}

// ConnectionFromContext 为模型调用取得本次执行的连接，不推断业务身份。
func ConnectionFromContext(ctx context.Context) (Connection, error) {
	e, err := ExecutionFromContext(ctx)
	if err != nil {
		return Connection{}, err
	}
	return e.AcquireDefault(ctx)
}
