package task

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/runtime/server"
	"github.com/JUXON-AI/jxpkg/credits"
	"github.com/JUXON-AI/jxpkg/lifecycle"
	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/JUXON-AI/jxpkg/safeerror"
)

// WorkerCaller 将已验证证书主体绑定到唯一任务队列。
type WorkerCaller struct {
	// Principal 是证书的唯一 SPIFFE URI SAN。
	Principal string `json:"principal"`
	// TaskType 是该工作负载可以访问的任务类型。
	TaskType string `json:"task_type"`
}

// WorkerServerConfig 由业务加载部署环境后显式传入，不读取业务 settings。
type WorkerServerConfig struct {
	// Address 是独立 HTTPS 监听地址。
	Address string
	// CertFile 是任务 API 服务端证书文件。
	CertFile string
	// KeyFile 是服务端私钥文件。
	KeyFile string
	// ClientCAFile 是验证 Worker 证书的 CA 文件。
	ClientCAFile string
	// Callers 是允许的证书主体和任务范围。
	Callers []WorkerCaller
}

// WorkerServer 只监听 mTLS 任务入口，不与网页身份或反向代理头回退。
type WorkerServer struct {
	address   string
	tlsConfig *tls.Config
	http      *http.Server
	mu        sync.Mutex
	listener  net.Listener
	closed    bool
	once      sync.Once
	closeErr  error
}

// NewWorkerServer 在启动前验证配置、证书与路由；Serve 显式启动监听。
func NewWorkerServer(cfg WorkerServerConfig, service, taskType string, auth WorkerConfig, acquire credits.AcquireFunc) (*WorkerServer, error) {
	if cfg.Address == "" {
		return nil, errors.New("task: invalid worker server configuration")
	}
	router := server.NewRouter("/v1/")
	if err := RegisterWorkerRoutes(router, service, taskType, auth, acquire, cfg.Callers...); err != nil {
		return nil, err
	}
	pair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, safeerror.Wrap("task: worker TLS unavailable", err)
	}
	pem, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, safeerror.Wrap("task: worker TLS unavailable", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("task: worker TLS unavailable")
	}
	return &WorkerServer{address: cfg.Address, tlsConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}, http: &http.Server{Handler: router.GinEngine(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 75 * time.Second, IdleTimeout: 90 * time.Second}}, nil
}

// Serve 同步创建独立端口，再异步服务；生命周期由业务显式管理。
func (s *WorkerServer) Serve() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.listener != nil {
		return errors.New("task: worker listener unavailable")
	}
	l, err := net.Listen("tcp", s.address)
	if err != nil {
		return safeerror.Wrap("task: worker listener unavailable", err)
	}
	s.listener = tls.NewListener(l, s.tlsConfig)
	go func() {
		err := s.http.Serve(s.listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logs.ErrorContextw(context.Background(), "task.worker.serve.failed", "error_kind", "listener")
			lifecycle.Std().Exit()
		}
	}()
	return nil
}

// Close 幂等停止接收请求，最长70秒等待任务长轮询排空。
func (s *WorkerServer) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
		defer cancel()
		s.closeErr = s.http.Shutdown(ctx)
		if s.closeErr != nil {
			s.closeErr = errors.Join(s.closeErr, s.http.Close())
		}
	})
	return s.closeErr
}
