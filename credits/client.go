// Package credits 提供服务端领取员工模型连接的协议客户端，不负责模型调用或扣费。
package credits

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/JUXON-AI/jxpkg/requestid"
	"github.com/JUXON-AI/jxpkg/safeerror"
)

// DefaultPath 是独立工作负载入口，不接受浏览器凭证。
const DefaultPath = "/internal/credits/default"

// ErrUnavailable 表示配置、网络或协议不可用，错误不包含凭证。
var ErrUnavailable = errors.New("credits unavailable")

// ErrDenied 表示员工尚未开通或不允许使用模型凭证。
var ErrDenied = errors.New("credits access denied")

func unavailableCause(cause error) error {
	if cause == nil {
		return ErrUnavailable
	}
	return safeerror.Wrap(ErrUnavailable.Error(), errors.Join(ErrUnavailable, cause))
}

// Subject 来自调用服务已验证的身份或权威任务记录。
type Subject struct {
	// CompanyID 是员工所属公司。
	CompanyID uint `json:"company_id"`
	// UIN 是员工的公司身份；服务端核对已有账户关联。
	UIN uint `json:"uin"`
}

// Connection 是只在本次执行内使用的模型凭证。
type Connection struct {
	// BaseURL 是 New API 的 OpenAI 兼容根地址，包含 /v1。
	BaseURL string `json:"base_url"`
	// APIKey 是员工 default 凭证，不得持久化或记录日志。
	APIKey string `json:"api_key"`
}

// TLSConfig 是客户端证书和服务端 CA 文件配置。
type TLSConfig struct {
	// CAFile 是验证额度服务证书的 CA 文件。
	CAFile string `yaml:"ca_file"`
	// CertFile 是本服务的客户端证书。
	CertFile string `yaml:"cert_file"`
	// KeyFile 是本服务的客户端私钥。
	KeyFile string `yaml:"key_file"`
}

// Config 由调用应用读取 coresetting 后传入。
type Config struct {
	// Endpoint 是额度服务 HTTPS 根地址。
	Endpoint string `yaml:"endpoint"`
	// Timeout 是单次领取的总超时，默认 15 秒，最大 45 秒。
	Timeout time.Duration `yaml:"timeout"`
	// TLS 是本服务专用的 mTLS 文件配置。
	TLS TLSConfig `yaml:"tls"`
}

// Client 复用 HTTP 连接池，不缓存员工凭证，不重试请求。
type Client struct {
	endpoint       string
	http           *http.Client
	ownedTransport bool
}

// NewClient 加载 mTLS 文件并创建客户端；关闭时回收空闲连接。
func NewClient(cfg Config) (*Client, error) {
	pair, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, unavailableCause(err)
	}
	pem, err := os.ReadFile(cfg.TLS.CAFile)
	if err != nil {
		return nil, unavailableCause(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, ErrUnavailable
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{pair}}
	client, err := NewClientWithTransport(cfg, transport)
	if err != nil {
		transport.CloseIdleConnections()
	}
	if client != nil {
		client.ownedTransport = true
	}
	return client, err
}

// NewClientWithTransport 接收调用方已配置工作负载认证的 transport；不接管其生命周期。
func NewClientWithTransport(cfg Config, transport http.RoundTripper) (*Client, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || len(cfg.Endpoint) > 512 || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || transport == nil {
		return nil, unavailableCause(err)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.Timeout <= 0 || cfg.Timeout > 45*time.Second {
		return nil, ErrUnavailable
	}
	return &Client{endpoint: strings.TrimRight(u.String(), "/"), http: &http.Client{Transport: transport, Timeout: cfg.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// AcquireDefault 只领取指定员工的连接，校验 HTTP、响应体和地址，不跟随重定向。
func (c *Client) AcquireDefault(ctx context.Context, subject Subject) (Connection, error) {
	var connection Connection
	if err := c.call(ctx, subject, DefaultPath, &connection); err != nil {
		return Connection{}, err
	}
	if err := ValidateConnection(connection); err != nil {
		return Connection{}, err
	}
	return connection, nil
}

func (c *Client) call(ctx context.Context, subject Subject, path string, result any) error {
	if c == nil || ctx == nil || subject.CompanyID == 0 || subject.UIN == 0 {
		return ErrDenied
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	body, err := json.Marshal(subject)
	if err != nil {
		return unavailableCause(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return unavailableCause(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if id := requestid.FromContext(ctx); id != "" {
		req.Header.Set("X-Request-Id", id)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return safeerror.Wrap(ctx.Err().Error(), errors.Join(ctx.Err(), err))
		}
		return unavailableCause(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusConflict {
		return ErrDenied
	}
	if resp.StatusCode != http.StatusOK {
		return ErrUnavailable
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return unavailableCause(err)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024+1))
	if err != nil || len(raw) > 16*1024 {
		return unavailableCause(err)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(result); err != nil {
		return unavailableCause(err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return unavailableCause(err)
	}
	return nil
}

// ValidateConnection 拒绝凭证 URL、非 HTTPS 地址和畸形 Key。
func ValidateConnection(c Connection) error {
	u, err := url.Parse(c.BaseURL)
	if err != nil || len(c.BaseURL) > 512 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.TrimRight(u.Path, "/") != "/v1" || len(c.APIKey) < 1 || len(c.APIKey) > 8192 || strings.ContainsAny(c.APIKey, " \t\r\n") {
		return unavailableCause(err)
	}
	return nil
}

// Close 回收客户端 transport 的空闲连接，不影响在途请求。
func (c *Client) Close() error {
	if c != nil && c.http != nil && c.ownedTransport {
		c.http.CloseIdleConnections()
	}
	return nil
}
