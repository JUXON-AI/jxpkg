package lifecycle

import (
	"context"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/JUXON-AI/jxpkg/logs"
)

var std *LifeCycle

// LifeCycle 应用生命周期管理器，支持信号监听、优雅退出和资源清理。
type LifeCycle struct {
	ctx         context.Context
	cancle      context.CancelFunc
	chExit      chan struct{}
	exitTimeout time.Duration
	listenSigs  []os.Signal
	preExitRun  []io.Closer
	closerMu    sync.Mutex
}

// New 创建生命周期实例，默认监听 SIGTERM 和 os.Interrupt，退出超时 15 秒。
func New() *LifeCycle {
	ctx, cancle := context.WithCancel(context.Background())
	return &LifeCycle{
		ctx:         ctx,
		cancle:      cancle,
		chExit:      make(chan struct{}),
		exitTimeout: time.Second * 15,
		listenSigs:  []os.Signal{syscall.SIGTERM, os.Interrupt},
	}
}

// SetSignals 设置需要监听的退出信号。
func (l *LifeCycle) SetSignals(sigs ...os.Signal) { l.listenSigs = sigs }

// Context 返回生命周期上下文，取消时表示应用正在退出。
func (l *LifeCycle) Context() context.Context { return l.ctx }

// C 返回一个 channel，退出时关闭。
func (l *LifeCycle) C() <-chan struct{} { return l.chExit }

// AddCloseFunc 注册退出时执行的清理函数。
func (l *LifeCycle) AddCloseFunc(f func() error) { l.AddCloser(newCloserFunc(f)) }

// AddCloser 注册退出时需关闭的资源。
func (l *LifeCycle) AddCloser(clr io.Closer) {
	l.closerMu.Lock()
	defer l.closerMu.Unlock()
	if l.preExitRun == nil {
		l.preExitRun = []io.Closer{clr}
		return
	}
	l.preExitRun = append(l.preExitRun, clr)
}

// SetTimeout 设置优雅退出的超时时间。
func (l *LifeCycle) SetTimeout(d time.Duration) { l.exitTimeout = d }

// Exit 主动触发退出流程（关闭 chExit channel）。
func (l *LifeCycle) Exit() { closeCh(l.chExit) }

// CancelContext 取消生命周期上下文，但不会触发退出。
func (l *LifeCycle) CancelContext() {
	if l.cancle != nil {
		select {
		case <-l.ctx.Done():
		default:
			l.cancle()
		}
	}
}

// WaitExit 阻塞等待退出信号或 Exit 调用，然后执行资源清理。
func (l *LifeCycle) WaitExit() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, l.listenSigs...)
	for {
		select {
		case sig := <-sigChan:
			logs.Infof("catch signal: %v", sig)
			for _, lisSig := range l.listenSigs {
				if lisSig == sig {
					logs.Warnf("^C exit.")
					l.exit()
					return
				}
			}
		case <-l.chExit:
			logs.Warnf("others exit.")
			l.exit()
			return
		}
	}
}

func (l *LifeCycle) exit() {
	if l.exitTimeout < time.Microsecond {
		logs.Warnf("Forced exit.")
		os.Exit(0)
	}
	go func() {
		timer := time.NewTimer(l.exitTimeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			logs.Warnf("Timeout. Forced exit.")
			os.Exit(1)
		}
	}()
	l.cancle()
	l.closerMu.Lock()
	closers := make([]io.Closer, len(l.preExitRun))
	copy(closers, l.preExitRun)
	l.closerMu.Unlock()
	var wg sync.WaitGroup
	wg.Add(len(closers))
	for _, v := range closers {
		go func(clr io.Closer) {
			defer wg.Done()
			if clr != nil {
				clr.Close()
			}
		}(v)
	}
	wg.Wait()
	time.Sleep(time.Second)
	os.Exit(0)
}

func closeCh(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}

type closerFunc struct{ f func() error }

func newCloserFunc(f func() error) io.Closer { return &closerFunc{f: f} }
func (c *closerFunc) Close() error           { return c.f() }

// Std 返回全局生命周期实例，未初始化时自动创建。
func Std() *LifeCycle {
	if std == nil {
		std = New()
	}
	return std
}
