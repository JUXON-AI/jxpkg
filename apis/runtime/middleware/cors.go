package middleware

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// defaultCORSMaxAge 是浏览器缓存成功预检结果的默认时长。
	defaultCORSMaxAge = 12 * time.Hour
)

var (
	// defaultCORSMethods 是默认允许跨源调用的 HTTP 方法集合。
	defaultCORSMethods = []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"}

	// defaultCORSHeaders 是默认允许跨源调用显式发送的请求头集合。
	defaultCORSHeaders = []string{"Accept", "Authorization", "Content-Type", "Env", DefaultCSRFHeader}

	// defaultCORSExposedHeaders 是默认允许浏览器脚本读取的响应头集合。
	defaultCORSExposedHeaders = []string{"Content-Length"}
)

// CORSOptions 配置严格的同源和精确跨源访问规则。
type CORSOptions struct {
	// AllowedOrigins 表示额外允许的完整 HTTP 或 HTTPS Origin，不支持通配符、后缀或请求反射。
	AllowedOrigins []string

	// AllowedMethods 表示预检和实际跨源请求允许使用的方法；为空时使用安全默认集合。
	AllowedMethods []string

	// AllowedHeaders 表示预检允许请求的非简单请求头；为空时使用安全默认集合。
	AllowedHeaders []string

	// ExposedHeaders 表示允许浏览器脚本读取的响应头；为空时使用默认集合。
	ExposedHeaders []string

	// ExternalOrigin 表示应用确认的外部同源 Origin；为空时只根据 TLS 和 Request.Host 判定。
	ExternalOrigin string
}

type normalizedCORSOptions struct {
	// allowedOrigins 保存调用方无法再修改的额外 Origin 集合。
	allowedOrigins map[string]struct{}

	// allowedMethods 保存调用方无法再修改的跨源方法集合。
	allowedMethods map[string]struct{}

	// allowedHeaders 保存小写请求头名称到规范响应名称的映射。
	allowedHeaders map[string]string

	// exposedHeaders 保存调用方无法再修改的暴露响应头列表。
	exposedHeaders []string

	// externalOrigin 保存应用确认的规范外部同源 Origin。
	externalOrigin string
}

// CORS 返回仅允许无 Origin 请求和精确同源请求的默认 CORS 中间件。
func CORS() gin.HandlerFunc {
	handler, err := NewCORS(CORSOptions{})
	if err != nil {
		panic(err)
	}
	return handler
}

// NewCORS 创建支持精确 Origin allowlist 的 CORS 中间件。
func NewCORS(options CORSOptions) (gin.HandlerFunc, error) {
	normalized, err := normalizeCORSOptions(options)
	if err != nil {
		return nil, err
	}

	return func(ctx *gin.Context) {
		writer := &corsResponseWriter{ResponseWriter: ctx.Writer}
		ctx.Writer = writer

		origins := ctx.Request.Header.Values("Origin")
		if len(origins) == 0 {
			ctx.Next()
			writer.ensureHeaders()
			return
		}
		if len(origins) != 1 {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}

		origin, err := canonicalOrigin(origins[0])
		if err != nil {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		sameOrigin, allowed := normalized.allows(ctx.Request, origin)
		if !allowed {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}

		if isCORSPreflight(ctx.Request) {
			method, headers, ok := normalized.validatePreflight(ctx.Request)
			if !ok {
				ctx.AbortWithStatus(http.StatusForbidden)
				return
			}
			writer.allow(origin, normalized.exposedHeaders)
			addVary(ctx.Writer.Header(), "Access-Control-Request-Method", "Access-Control-Request-Headers")
			ctx.Header("Access-Control-Allow-Methods", method)
			if len(headers) != 0 {
				ctx.Header("Access-Control-Allow-Headers", strings.Join(headers, ", "))
			}
			ctx.Header("Access-Control-Max-Age", strconv.FormatInt(int64(defaultCORSMaxAge/time.Second), 10))
			ctx.AbortWithStatus(http.StatusNoContent)
			return
		}

		if !sameOrigin {
			if _, ok := normalized.allowedMethods[ctx.Request.Method]; !ok {
				ctx.AbortWithStatus(http.StatusForbidden)
				return
			}
		}
		writer.allow(origin, normalized.exposedHeaders)
		ctx.Next()
		writer.ensureHeaders()
	}, nil
}

// corsResponseWriter 在响应真正提交前恢复经过校验的 CORS 响应头。
type corsResponseWriter struct {
	gin.ResponseWriter

	// origin 保存本次请求经过精确校验的 Origin。
	origin string

	// exposedHeaders 保存允许浏览器脚本读取的响应头。
	exposedHeaders []string
}

var _ gin.ResponseWriter = (*corsResponseWriter)(nil)

func (writer *corsResponseWriter) allow(origin string, exposedHeaders []string) {
	writer.origin = origin
	writer.exposedHeaders = exposedHeaders
	writer.ensureHeaders()
}

func (writer *corsResponseWriter) ensureHeaders() {
	headers := writer.Header()
	addVary(headers, "Origin")
	if writer.origin == "" {
		headers.Del("Access-Control-Allow-Origin")
		headers.Del("Access-Control-Allow-Credentials")
		headers.Del("Access-Control-Expose-Headers")
		return
	}
	setAllowedCORSHeaders(headers, writer.origin, writer.exposedHeaders)
}

func (writer *corsResponseWriter) WriteHeader(statusCode int) {
	writer.ensureHeaders()
	writer.ResponseWriter.WriteHeader(statusCode)
}

func (writer *corsResponseWriter) WriteHeaderNow() {
	writer.ensureHeaders()
	writer.ResponseWriter.WriteHeaderNow()
}

func (writer *corsResponseWriter) Write(data []byte) (int, error) {
	writer.ensureHeaders()
	return writer.ResponseWriter.Write(data)
}

func (writer *corsResponseWriter) WriteString(data string) (int, error) {
	writer.ensureHeaders()
	return writer.ResponseWriter.WriteString(data)
}

func (writer *corsResponseWriter) Flush() {
	writer.ensureHeaders()
	writer.ResponseWriter.Flush()
}

// Unwrap 允许 net/http.ResponseController 继续访问底层 ResponseWriter。
func (writer *corsResponseWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}

func normalizeCORSOptions(options CORSOptions) (normalizedCORSOptions, error) {
	allowedOrigins := make(map[string]struct{}, len(options.AllowedOrigins))
	for _, value := range options.AllowedOrigins {
		origin, err := canonicalOrigin(value)
		if err != nil {
			return normalizedCORSOptions{}, fmt.Errorf("invalid allowed origin %q: %w", value, err)
		}
		allowedOrigins[origin] = struct{}{}
	}

	externalOrigin := ""
	if options.ExternalOrigin != "" {
		var err error
		externalOrigin, err = canonicalOrigin(options.ExternalOrigin)
		if err != nil {
			return normalizedCORSOptions{}, fmt.Errorf("invalid external origin %q: %w", options.ExternalOrigin, err)
		}
	}

	methods := options.AllowedMethods
	if len(methods) == 0 {
		methods = defaultCORSMethods
	}
	allowedMethods := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		if method == "" || method == "*" || method != strings.ToUpper(method) || !validToken(method) {
			return normalizedCORSOptions{}, fmt.Errorf("invalid allowed method %q", method)
		}
		allowedMethods[method] = struct{}{}
	}

	headers := options.AllowedHeaders
	if len(headers) == 0 {
		headers = defaultCORSHeaders
	}
	allowedHeaders, err := normalizeHeaderNames(headers)
	if err != nil {
		return normalizedCORSOptions{}, fmt.Errorf("invalid allowed header: %w", err)
	}

	exposed := options.ExposedHeaders
	if len(exposed) == 0 {
		exposed = defaultCORSExposedHeaders
	}
	exposedHeaders, err := normalizedHeaderList(exposed)
	if err != nil {
		return normalizedCORSOptions{}, fmt.Errorf("invalid exposed header: %w", err)
	}

	return normalizedCORSOptions{
		allowedOrigins: allowedOrigins,
		allowedMethods: allowedMethods,
		allowedHeaders: allowedHeaders,
		exposedHeaders: exposedHeaders,
		externalOrigin: externalOrigin,
	}, nil
}

func canonicalOrigin(value string) (string, error) {
	if value == "" || value == "null" || strings.TrimSpace(value) != value || strings.Contains(value, "\\") {
		return "", fmt.Errorf("origin must be a canonical HTTP or HTTPS origin")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("origin must contain only scheme and host")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("origin scheme must be http or https")
	}
	if err := validateCanonicalHost(parsed.Host); err != nil {
		return "", fmt.Errorf("origin host is not canonical")
	}
	canonical := parsed.Scheme + "://" + parsed.Host
	if canonical != value {
		return "", fmt.Errorf("origin is not canonical")
	}
	return canonical, nil
}

func (options normalizedCORSOptions) allows(request *http.Request, origin string) (bool, bool) {
	target := options.externalOrigin
	if target == "" {
		if err := validateCanonicalHost(request.Host); err != nil {
			return false, false
		}
		scheme := "http"
		if request.TLS != nil {
			scheme = "https"
		}
		target = scheme + "://" + request.Host
	}
	if origin == target {
		return true, true
	}
	_, ok := options.allowedOrigins[origin]
	return false, ok
}

func isCORSPreflight(request *http.Request) bool {
	return request.Method == http.MethodOptions && len(request.Header.Values("Access-Control-Request-Method")) != 0
}

func (options normalizedCORSOptions) validatePreflight(request *http.Request) (string, []string, bool) {
	methods := request.Header.Values("Access-Control-Request-Method")
	if len(methods) != 1 || methods[0] == "" || methods[0] != strings.ToUpper(methods[0]) || !validToken(methods[0]) {
		return "", nil, false
	}
	if _, ok := options.allowedMethods[methods[0]]; !ok {
		return "", nil, false
	}

	headers, ok := requestedHeaderNames(request.Header.Values("Access-Control-Request-Headers"), options.allowedHeaders)
	if !ok {
		return "", nil, false
	}
	return methods[0], headers, true
}

func requestedHeaderNames(values []string, allowed map[string]string) ([]string, bool) {
	if len(values) == 0 {
		return nil, true
	}
	result := make([]string, 0)
	seen := make(map[string]struct{})
	for _, value := range values {
		for _, name := range strings.Split(value, ",") {
			name = strings.TrimSpace(name)
			lower := strings.ToLower(name)
			canonical, ok := allowed[lower]
			if name == "" || !validToken(name) || !ok {
				return nil, false
			}
			if _, duplicate := seen[lower]; duplicate {
				continue
			}
			seen[lower] = struct{}{}
			result = append(result, canonical)
		}
	}
	return result, true
}

func normalizeHeaderNames(values []string) (map[string]string, error) {
	result := make(map[string]string, len(values))
	for _, value := range values {
		if value == "" || value == "*" || strings.TrimSpace(value) != value || !validToken(value) {
			return nil, fmt.Errorf("invalid header name %q", value)
		}
		canonical := http.CanonicalHeaderKey(value)
		result[strings.ToLower(value)] = canonical
	}
	return result, nil
}

func normalizedHeaderList(values []string) ([]string, error) {
	lookup, err := normalizeHeaderNames(values)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(lookup))
	seen := make(map[string]struct{}, len(lookup))
	for _, value := range values {
		lower := strings.ToLower(value)
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		result = append(result, lookup[lower])
	}
	return result, nil
}

func setAllowedCORSHeaders(headers http.Header, origin string, exposed []string) {
	headers.Set("Access-Control-Allow-Origin", origin)
	headers.Set("Access-Control-Allow-Credentials", "true")
	if len(exposed) != 0 {
		headers.Set("Access-Control-Expose-Headers", strings.Join(exposed, ", "))
	}
	addVary(headers, "Origin")
}

func addVary(headers http.Header, values ...string) {
	existing := make([]string, 0)
	seen := make(map[string]struct{})
	for _, line := range headers.Values("Vary") {
		for _, value := range strings.Split(line, ",") {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			lower := strings.ToLower(value)
			if _, ok := seen[lower]; ok {
				continue
			}
			seen[lower] = struct{}{}
			existing = append(existing, value)
		}
	}
	for _, value := range values {
		lower := strings.ToLower(value)
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		existing = append(existing, value)
	}
	headers.Set("Vary", strings.Join(existing, ", "))
}
