package middleware

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
)

const (
	// DefaultCSRFHeader 是浏览器会话路由默认读取的 CSRF Header。
	DefaultCSRFHeader = "X-CSRF-Token"
)

// BrowserSessionOptions 配置浏览器 Cookie Session 和 CSRF 中间件。
type BrowserSessionOptions struct {
	// Service 表示传给会话解析器的静态服务标识。
	Service string

	// CookieName 表示当前业务 Host 唯一允许的 __Host- Session Cookie 名称。
	CookieName string

	// AllowedHosts 表示该服务精确允许的规范 Host 集合。
	AllowedHosts map[string]struct{}

	// Resolver 表示受信任的会话主体解析器。
	Resolver auth.SessionResolver

	// Clock 提供会话期限校验使用的当前时间。
	Clock func() time.Time

	// CSRFHeader 表示副作用请求携带 CSRF Token 的 Header 名称。
	CSRFHeader string

	// UnsafeMethods 表示必须执行 Origin 和 CSRF 校验的 HTTP Method 集合。
	UnsafeMethods map[string]struct{}
}

type normalizedBrowserSessionOptions struct {
	// service 保存已校验的静态服务标识。
	service string

	// cookieName 保存已校验的 Session Cookie 名称。
	cookieName string

	// allowedHosts 保存调用方无法再修改的 Host Allowlist 副本。
	allowedHosts map[string]struct{}

	// resolver 保存受信任的会话主体解析器。
	resolver auth.SessionResolver

	// clock 保存会话期限校验使用的时钟。
	clock func() time.Time

	// csrfHeader 保存已校验的 CSRF Header 名称。
	csrfHeader string

	// unsafeMethods 保存调用方无法再修改的副作用 Method 集合副本。
	unsafeMethods map[string]struct{}
}

// NewBrowserSessionMiddleware 创建严格解析当前 Host Cookie Session 的中间件。
func NewBrowserSessionMiddleware(options BrowserSessionOptions) (gin.HandlerFunc, error) {
	normalized, err := normalizeBrowserSessionOptions(options, true)
	if err != nil {
		return nil, err
	}

	return func(ctx *gin.Context) {
		ls := &auth.LoginStatus{AuthMode: auth.AuthModeBrowserSession}
		ctx.Set(constants.CtxKeyLoginStatus, ls)

		if len(ctx.Request.Header.Values("Authorization")) != 0 {
			failLoginStatus(ls, auth.ErrInvalidCredential)
			return
		}

		host, err := allowedCanonicalHost(ctx.Request.Host, normalized.allowedHosts)
		if err != nil {
			failLoginStatus(ls, err)
			return
		}

		cookies := matchingCookies(ctx.Request, normalized.cookieName)
		if len(cookies) == 0 {
			return
		}
		if len(cookies) != 1 || cookies[0].Value == "" || strings.TrimSpace(cookies[0].Value) != cookies[0].Value {
			failLoginStatus(ls, auth.ErrInvalidCredential)
			return
		}

		principal, err := normalized.resolver.Resolve(ctx.Request.Context(), auth.SessionResolveRequest{
			Host:      host,
			Service:   normalized.service,
			SessionID: cookies[0].Value,
		})
		if err != nil {
			failLoginStatus(ls, resolverError(err))
			return
		}
		if err := validateSessionPrincipal(principal, host, normalized.clock()); err != nil {
			failLoginStatus(ls, err)
			return
		}

		ctx.Set(constants.CtxKeyLoginStatus, auth.NewBrowserSessionLoginStatus(*principal))
	}, nil
}

func normalizeBrowserSessionOptions(options BrowserSessionOptions, requireResolver bool) (normalizedBrowserSessionOptions, error) {
	service := strings.TrimSpace(options.Service)
	if service == "" || service != options.Service {
		return normalizedBrowserSessionOptions{}, fmt.Errorf("%w: service must be a non-empty canonical value", auth.ErrAuthBackendUnavailable)
	}
	if !strings.HasPrefix(options.CookieName, "__Host-") || len(options.CookieName) == len("__Host-") {
		return normalizedBrowserSessionOptions{}, fmt.Errorf("%w: browser session cookie must use __Host- prefix", auth.ErrAuthBackendUnavailable)
	}
	if err := validateCookieName(options.CookieName); err != nil {
		return normalizedBrowserSessionOptions{}, err
	}
	if len(options.AllowedHosts) == 0 {
		return normalizedBrowserSessionOptions{}, fmt.Errorf("%w: allowed hosts are empty", auth.ErrAuthBackendUnavailable)
	}
	allowedHosts := make(map[string]struct{}, len(options.AllowedHosts))
	for host := range options.AllowedHosts {
		if err := validateCanonicalHost(host); err != nil {
			return normalizedBrowserSessionOptions{}, fmt.Errorf("%w: invalid allowed host", auth.ErrAuthBackendUnavailable)
		}
		allowedHosts[host] = struct{}{}
	}
	if requireResolver && options.Resolver == nil {
		return normalizedBrowserSessionOptions{}, fmt.Errorf("%w: session resolver is nil", auth.ErrAuthBackendUnavailable)
	}

	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	csrfHeader := options.CSRFHeader
	if csrfHeader == "" {
		csrfHeader = DefaultCSRFHeader
	}
	if strings.TrimSpace(csrfHeader) != csrfHeader || !validToken(csrfHeader) {
		return normalizedBrowserSessionOptions{}, fmt.Errorf("%w: invalid csrf header", auth.ErrAuthBackendUnavailable)
	}

	unsafeMethods := map[string]struct{}{
		"POST":   {},
		"PUT":    {},
		"PATCH":  {},
		"DELETE": {},
	}
	for method := range options.UnsafeMethods {
		if method == "" || method != strings.ToUpper(method) || !validToken(method) {
			return normalizedBrowserSessionOptions{}, fmt.Errorf("%w: invalid unsafe method", auth.ErrAuthBackendUnavailable)
		}
		unsafeMethods[method] = struct{}{}
	}

	return normalizedBrowserSessionOptions{
		service:       service,
		cookieName:    options.CookieName,
		allowedHosts:  allowedHosts,
		resolver:      options.Resolver,
		clock:         clock,
		csrfHeader:    csrfHeader,
		unsafeMethods: unsafeMethods,
	}, nil
}

func resolverError(err error) error {
	if errors.Is(err, auth.ErrInvalidCredential) || errors.Is(err, auth.ErrInvalidPrincipal) {
		return auth.ErrInvalidCredential
	}
	return fmt.Errorf("%w: resolve browser session", auth.ErrAuthBackendUnavailable)
}

func validateSessionPrincipal(principal *auth.SessionPrincipal, host string, now time.Time) error {
	if principal == nil {
		return auth.ErrInvalidCredential
	}
	if principal.Host != host {
		return auth.ErrInvalidCredential
	}
	if principal.Claims.UserID == 0 || principal.Claims.UIN == 0 || principal.Claims.CompanyID == 0 {
		return auth.ErrInvalidPrincipal
	}
	if principal.ClientID == "" || strings.TrimSpace(principal.ClientID) != principal.ClientID ||
		principal.SessionVersion == 0 || principal.AuthenticatedAt <= 0 ||
		principal.IdleExpiresAt <= 0 || principal.AbsoluteExpiresAt <= 0 ||
		principal.AuthenticatedAt > now.Unix() || principal.AuthenticatedAt > principal.IdleExpiresAt ||
		principal.AuthenticatedAt > principal.AbsoluteExpiresAt || principal.IdleExpiresAt > principal.AbsoluteExpiresAt ||
		len(principal.CSRFTokenHash) != sha256.Size {
		return fmt.Errorf("%w: invalid session principal metadata", auth.ErrAuthBackendUnavailable)
	}
	if principal.IdleExpiresAt <= now.Unix() || principal.AbsoluteExpiresAt <= now.Unix() {
		return auth.ErrInvalidCredential
	}
	return nil
}

func allowedCanonicalHost(host string, allowedHosts map[string]struct{}) (string, error) {
	if err := validateCanonicalHost(host); err != nil {
		return "", auth.ErrInvalidCredential
	}
	if _, ok := allowedHosts[host]; !ok {
		return "", auth.ErrInvalidCredential
	}
	return host, nil
}

func validateCanonicalHost(host string) error {
	if host == "" || host != strings.ToLower(host) || strings.TrimSpace(host) != host || strings.Contains(host, "\\") {
		return auth.ErrInvalidCredential
	}
	parsed, err := url.Parse("http://" + host)
	if err != nil || parsed.Host != host || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return auth.ErrInvalidCredential
	}
	hostname := parsed.Hostname()
	if hostname == "" || strings.HasSuffix(hostname, ".") || strings.HasSuffix(host, ":") {
		return auth.ErrInvalidCredential
	}
	if ip := net.ParseIP(hostname); ip == nil {
		if strings.Trim(hostname, "0123456789.") == "" {
			return auth.ErrInvalidCredential
		}
		if err := validateDNSName(hostname); err != nil {
			return err
		}
	} else if ip.String() != hostname {
		return auth.ErrInvalidCredential
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 || strconv.Itoa(value) != port {
			return auth.ErrInvalidCredential
		}
	}
	return nil
}

func validateDNSName(hostname string) error {
	if len(hostname) > 253 {
		return auth.ErrInvalidCredential
	}
	for _, label := range strings.Split(hostname, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return auth.ErrInvalidCredential
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return auth.ErrInvalidCredential
			}
		}
	}
	return nil
}

func validToken(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char <= 0x20 || char >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}\t", char) {
			return false
		}
	}
	return true
}
