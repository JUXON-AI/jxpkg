package middleware

import (
	"strings"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
)

// NewCSRFMiddleware 创建浏览器会话副作用请求的精确 Origin 和 CSRF 校验中间件。
func NewCSRFMiddleware(options BrowserSessionOptions) (gin.HandlerFunc, error) {
	normalized, err := normalizeBrowserSessionOptions(options, false)
	if err != nil {
		return nil, err
	}

	return func(ctx *gin.Context) {
		if _, unsafe := normalized.unsafeMethods[strings.ToUpper(ctx.Request.Method)]; !unsafe {
			return
		}

		value, ok := ctx.Get(constants.CtxKeyLoginStatus)
		ls, valid := value.(*auth.LoginStatus)
		if !ok || !valid || ls.State != auth.StateSucc || ls.AuthMode != auth.AuthModeBrowserSession {
			abortAuth(ctx, ls)
			return
		}
		if _, err := allowedCanonicalHost(ctx.Request.Host, normalized.allowedHosts); err != nil {
			failLoginStatus(ls, err)
			abortAuth(ctx, ls)
			return
		}
		if !validRequestOrigin(ctx, normalized.externalOrigin) {
			failLoginStatus(ls, auth.ErrInvalidCredential)
			abortAuth(ctx, ls)
			return
		}

		tokens := ctx.Request.Header.Values(normalized.csrfHeader)
		if len(tokens) != 1 || tokens[0] == "" {
			failLoginStatus(ls, auth.ErrInvalidCredential)
			abortAuth(ctx, ls)
			return
		}
		if !ls.MatchesBrowserCSRF(tokens[0]) {
			failLoginStatus(ls, auth.ErrInvalidCredential)
			abortAuth(ctx, ls)
			return
		}
	}, nil
}

func validRequestOrigin(ctx *gin.Context, externalOrigin string) bool {
	origins := ctx.Request.Header.Values("Origin")
	if len(origins) != 1 {
		return false
	}
	origin, err := canonicalOrigin(origins[0])
	if err != nil {
		return false
	}
	target := externalOrigin
	if target == "" {
		scheme := "http"
		if ctx.Request.TLS != nil {
			scheme = "https"
		}
		target = scheme + "://" + ctx.Request.Host
	}
	return origin == target
}
