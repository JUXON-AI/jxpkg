package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// InternalSessionResolvePath 是 Account 内部会话解析接口的固定路径。
	InternalSessionResolvePath = "/internal/session/resolve"

	maximumSessionResolveResponseBytes = 16 * 1024
	maximumOpaqueSessionIDBytes        = 4 * 1024
)

// SessionResolverClientOptions 配置内部会话解析客户端。
type SessionResolverClientOptions struct {
	// Endpoint 表示固定的 HTTPS Account 内部会话解析地址。
	Endpoint string

	// Service 表示由工作负载注册表分配的静态服务标识。
	Service string

	// Transport 表示注入工作负载认证或 mTLS 的专用 HTTP Transport。
	Transport http.RoundTripper

	// Timeout 表示一次权威会话解析的总超时时间。
	Timeout time.Duration
}

// InternalSessionResolverClient 通过受认证的内部 HTTP 接口解析浏览器会话。
type InternalSessionResolverClient struct {
	endpoint                string
	companyIdentityEndpoint string
	service                 string
	client                  *http.Client
}

var _ SessionResolver = (*InternalSessionResolverClient)(nil)

// SessionResolveResponse is the fixed JSON representation shared by resolver peers.
type SessionResolveResponse struct {
	// UserID 表示系统全局用户标识。
	UserID uint `json:"user_id"`

	// UIN 表示当前业务身份标识。
	UIN uint `json:"uin"`

	// CompanyID 表示当前公司标识。
	CompanyID uint `json:"company_id"`

	// MembershipEpoch 表示成员身份代次。
	MembershipEpoch uint64 `json:"membership_epoch"`

	// Host 表示会话绑定的规范 Host。
	Host string `json:"host"`

	// ClientID 表示创建会话的静态客户端标识。
	ClientID string `json:"client_id"`

	// SessionVersion 表示会话撤销与轮换版本。
	SessionVersion uint64 `json:"session_version"`

	// AuthenticatedAt 表示中央认证完成的 Unix 时间戳。
	AuthenticatedAt int64 `json:"authenticated_at"`

	// IdleExpiresAt 表示会话空闲过期的 Unix 时间戳。
	IdleExpiresAt int64 `json:"idle_expires_at"`

	// AbsoluteExpiresAt 表示会话绝对过期的 Unix 时间戳。
	AbsoluteExpiresAt int64 `json:"absolute_expires_at"`

	// CSRFTokenHash 表示 Base64URL 编码的会话 CSRF SHA-256 摘要。
	CSRFTokenHash string `json:"csrf_token_hash"`
}

// NewInternalSessionResolverClient 创建不使用环境代理、缓存或自动重试的内部解析客户端。
func NewInternalSessionResolverClient(options SessionResolverClientOptions) (*InternalSessionResolverClient, error) {
	endpoint, err := normalizeSessionResolveEndpoint(options.Endpoint)
	if err != nil {
		return nil, err
	}
	if !validSessionResolveIdentifier(options.Service) {
		return nil, fmt.Errorf("%w: resolver service must be a non-empty canonical value", ErrAuthBackendUnavailable)
	}
	if options.Transport == nil {
		return nil, fmt.Errorf("%w: authenticated resolver transport is required", ErrAuthBackendUnavailable)
	}
	if options.Timeout <= 0 {
		return nil, fmt.Errorf("%w: resolver timeout must be positive", ErrAuthBackendUnavailable)
	}
	return &InternalSessionResolverClient{
		endpoint:                endpoint,
		companyIdentityEndpoint: strings.TrimSuffix(endpoint, InternalSessionResolvePath) + InternalCompanyIdentityResolvePath,
		service:                 options.Service,
		client: &http.Client{
			Transport: options.Transport,
			Timeout:   options.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Resolve 使用配置的服务身份和请求 Host/SID 获取最小主体快照。
func (client *InternalSessionResolverClient) Resolve(ctx context.Context, request SessionResolveRequest) (*SessionPrincipal, error) {
	if client == nil || client.client == nil {
		return nil, fmt.Errorf("%w: session resolver client is not configured", ErrAuthBackendUnavailable)
	}
	if request.Service != client.service {
		return nil, ErrInvalidCredential
	}
	if !validSessionResolveHost(request.Host) || !validOpaqueSessionID(request.SessionID) {
		return nil, ErrInvalidCredential
	}
	body, err := json.Marshal(SessionResolveRequest{
		Host: request.Host, Service: client.service, SessionID: request.SessionID,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode session resolve request", ErrAuthBackendUnavailable)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: create session resolve request", ErrAuthBackendUnavailable)
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Cache-Control", "no-store")

	response, err := client.client.Do(httpRequest)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrAuthBackendUnavailable, ctxErr)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: %w", ErrAuthBackendUnavailable, context.DeadlineExceeded)
		}
		return nil, fmt.Errorf("%w: session resolve transport", ErrAuthBackendUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusNotFound {
		return nil, ErrInvalidCredential
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: session resolve returned status %d", ErrAuthBackendUnavailable, response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, fmt.Errorf("%w: invalid session resolve content type", ErrAuthBackendUnavailable)
	}
	if response.ContentLength > maximumSessionResolveResponseBytes {
		return nil, fmt.Errorf("%w: session resolve response is too large", ErrAuthBackendUnavailable)
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, maximumSessionResolveResponseBytes+1))
	if err != nil || len(document) > maximumSessionResolveResponseBytes {
		return nil, fmt.Errorf("%w: read session resolve response", ErrAuthBackendUnavailable)
	}
	if err := validateJSONObject(document); err != nil {
		return nil, fmt.Errorf("%w: invalid session resolve response", ErrAuthBackendUnavailable)
	}
	var wire SessionResolveResponse
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return nil, fmt.Errorf("%w: decode session resolve response", ErrAuthBackendUnavailable)
	}
	csrfHash, err := base64.RawURLEncoding.Strict().DecodeString(wire.CSRFTokenHash)
	if err != nil || len(csrfHash) != sha256.Size {
		return nil, fmt.Errorf("%w: invalid session resolve principal", ErrAuthBackendUnavailable)
	}
	principal := &SessionPrincipal{
		Claims: UserClaims{
			UserID:          wire.UserID,
			UIN:             wire.UIN,
			CompanyID:       wire.CompanyID,
			MembershipEpoch: wire.MembershipEpoch,
		},
		Host:              wire.Host,
		ClientID:          wire.ClientID,
		SessionVersion:    wire.SessionVersion,
		AuthenticatedAt:   wire.AuthenticatedAt,
		IdleExpiresAt:     wire.IdleExpiresAt,
		AbsoluteExpiresAt: wire.AbsoluteExpiresAt,
		CSRFTokenHash:     csrfHash,
	}
	if wire.UserID == 0 || wire.UIN == 0 || wire.CompanyID == 0 || wire.MembershipEpoch == 0 || wire.Host != request.Host ||
		!validSessionResolveIdentifier(wire.ClientID) || wire.SessionVersion == 0 ||
		wire.AuthenticatedAt <= 0 || wire.IdleExpiresAt <= 0 || wire.AbsoluteExpiresAt <= 0 ||
		wire.AuthenticatedAt > wire.IdleExpiresAt || wire.IdleExpiresAt > wire.AbsoluteExpiresAt {
		return nil, fmt.Errorf("%w: invalid session resolve principal", ErrAuthBackendUnavailable)
	}
	return principal, nil
}

func normalizeSessionResolveEndpoint(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != InternalSessionResolvePath || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: invalid session resolve endpoint", ErrAuthBackendUnavailable)
	}
	if !validSessionResolveHost(parsed.Host) {
		return "", fmt.Errorf("%w: invalid session resolve endpoint", ErrAuthBackendUnavailable)
	}
	return parsed.String(), nil
}

func validSessionResolveHost(host string) bool {
	if host == "" || host != strings.TrimSpace(host) || host != strings.ToLower(host) || strings.Contains(host, "\\") {
		return false
	}
	parsed, err := url.Parse("https://" + host)
	if err != nil || parsed.Host != host || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	hostname := parsed.Hostname()
	if hostname == "" || strings.HasSuffix(hostname, ".") || strings.HasSuffix(host, ":") {
		return false
	}
	if ip := net.ParseIP(hostname); ip == nil {
		if strings.Trim(hostname, "0123456789.") == "" || !validSessionResolveDNSName(hostname) {
			return false
		}
	} else if ip.String() != hostname {
		return false
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 || strconv.Itoa(value) != port {
			return false
		}
	}
	return true
}

func validSessionResolveDNSName(hostname string) bool {
	if len(hostname) > 253 {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validSessionResolveIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func validOpaqueSessionID(sessionID string) bool {
	return sessionID != "" && len(sessionID) <= maximumOpaqueSessionIDBytes && sessionID == strings.TrimSpace(sessionID) && !strings.ContainsAny(sessionID, "\x00\r\n")
}
