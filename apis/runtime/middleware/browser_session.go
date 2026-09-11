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

// BrowserSessionBinding binds one exact canonical Host to its browser identity boundary.
type BrowserSessionBinding struct {
	// Host includes an explicit port when that port is part of the boundary.
	Host string
	// Service is the authoritative resolver's registered service identifier.
	Service string
	// CookieName is the Host-only __Host- session cookie for this Host.
	CookieName string
	// ExternalOrigin 表示应用确认的外部同源 Origin；为空时根据 TLS 和 Request.Host 判定。
	ExternalOrigin string
}

// BrowserSessionOptions 配置浏览器 Cookie Session 和 CSRF 中间件。
type BrowserSessionOptions struct {
	// Bindings is copied and validated at construction; Hosts must be unique.
	Bindings []BrowserSessionBinding

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
	// bindings owns immutable value copies indexed by exact Host.
	bindings map[string]BrowserSessionBinding

	// resolver 保存受信任的会话主体解析器。
	resolver auth.SessionResolver

	// clock 保存会话期限校验使用的时钟。
	clock func() time.Time

	// csrfHeader 保存已校验的 CSRF Header 名称。
	csrfHeader string

	// unsafeMethods 保存调用方无法再修改的副作用 Method 集合副本。
	unsafeMethods map[string]struct{}
}

// BrowserSessionHandlers contains the three route boundaries sharing one
// immutable, startup-validated Host directory.
type BrowserSessionHandlers struct {
	// Session resolves the current Host's browser principal.
	Session gin.HandlerFunc
	// CSRF verifies unsafe requests against that Host's origin and session token.
	CSRF gin.HandlerFunc
	// Bearer rejects the current Host's browser cookie before token verification.
	Bearer gin.HandlerFunc
}

// NewBrowserSessionHandlers validates once and shares one frozen Host directory
// across the Session, CSRF and Bearer route boundaries.
func NewBrowserSessionHandlers(options BrowserSessionOptions) (BrowserSessionHandlers, error) {
	normalized, err := normalizeBrowserSessionOptions(options)
	if err != nil {
		return BrowserSessionHandlers{}, err
	}
	return BrowserSessionHandlers{
		Session: browserSessionMiddleware(normalized),
		CSRF:    csrfMiddleware(normalized),
		Bearer:  browserBearerMiddleware(normalized.bindings),
	}, nil
}

func browserSessionMiddleware(normalized normalizedBrowserSessionOptions) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ls := &auth.LoginStatus{AuthMode: auth.AuthModeBrowserSession}
		ctx.Set(constants.CtxKeyLoginStatus, ls)

		if len(ctx.Request.Header.Values("Authorization")) != 0 {
			failLoginStatus(ls, auth.ErrInvalidCredential)
			return
		}

		host := ctx.Request.Host
		binding, ok := normalized.bindings[host]
		if !ok {
			failLoginStatus(ls, auth.ErrInvalidCredential)
			return
		}

		cookies := matchingCookies(ctx.Request, binding.CookieName)
		if len(cookies) == 0 {
			return
		}
		if len(cookies) != 1 || cookies[0].Value == "" || strings.TrimSpace(cookies[0].Value) != cookies[0].Value {
			failLoginStatus(ls, auth.ErrInvalidCredential)
			return
		}

		principal, err := normalized.resolver.Resolve(ctx.Request.Context(), auth.SessionResolveRequest{
			Host:      host,
			Service:   binding.Service,
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
	}
}

func normalizeBrowserSessionOptions(options BrowserSessionOptions) (normalizedBrowserSessionOptions, error) {
	if len(options.Bindings) == 0 {
		return normalizedBrowserSessionOptions{}, fmt.Errorf("%w: browser bindings are empty", auth.ErrAuthBackendUnavailable)
	}
	bindings := make(map[string]BrowserSessionBinding, len(options.Bindings))
	for _, binding := range options.Bindings {
		if err := validateBrowserSessionBinding(binding); err != nil {
			return normalizedBrowserSessionOptions{}, err
		}
		if _, exists := bindings[binding.Host]; exists {
			return normalizedBrowserSessionOptions{}, fmt.Errorf("%w: duplicate browser binding host", auth.ErrAuthBackendUnavailable)
		}
		bindings[binding.Host] = binding
	}
	if options.Resolver == nil {
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
		bindings:      bindings,
		resolver:      options.Resolver,
		clock:         clock,
		csrfHeader:    csrfHeader,
		unsafeMethods: unsafeMethods,
	}, nil
}

func validateBrowserSessionBinding(binding BrowserSessionBinding) error {
	if binding.Service == "" || strings.TrimSpace(binding.Service) != binding.Service {
		return fmt.Errorf("%w: invalid browser binding service", auth.ErrAuthBackendUnavailable)
	}
	if err := validateCanonicalHost(binding.Host); err != nil {
		return fmt.Errorf("%w: invalid browser binding host", auth.ErrAuthBackendUnavailable)
	}
	if !strings.HasPrefix(binding.CookieName, "__Host-") || len(binding.CookieName) == len("__Host-") {
		return fmt.Errorf("%w: browser session cookie must use __Host- prefix", auth.ErrAuthBackendUnavailable)
	}
	if err := validateCookieName(binding.CookieName); err != nil {
		return err
	}
	if binding.ExternalOrigin != "" {
		origin, err := canonicalOrigin(binding.ExternalOrigin)
		if err != nil {
			return fmt.Errorf("%w: invalid external origin", auth.ErrAuthBackendUnavailable)
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Host != binding.Host {
			return fmt.Errorf("%w: external origin host differs from binding host", auth.ErrAuthBackendUnavailable)
		}
	}
	return nil
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
	if principal.Claims.UserID == 0 || principal.Claims.UIN == 0 || principal.Claims.CompanyID == 0 || principal.Claims.MembershipEpoch == 0 {
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
