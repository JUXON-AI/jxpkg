package task

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/JUXON-AI/jxpkg/credits"
)

// NewWorkerHTTPClient 用显式 mTLS 文件配置创建任务客户端；调用方负责关闭空闲连接。
func NewWorkerHTTPClient(cfg credits.TLSConfig, timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 || timeout > 2*time.Minute {
		return nil, errors.New("task: invalid worker timeout")
	}
	pair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, errors.New("task: worker TLS unavailable")
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, errors.New("task: worker TLS unavailable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("task: worker TLS unavailable")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.RegisterProtocol("http", rejectWorkerHTTP{})
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{pair}}
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// rejectWorkerHTTP 防止专用 mTLS 客户端经明文 HTTP 发送任务令牌。
type rejectWorkerHTTP struct{}

func (rejectWorkerHTTP) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("task: worker HTTPS required")
}
