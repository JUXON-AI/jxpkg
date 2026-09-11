package middleware

import (
	"strings"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
)

func csrfMiddleware(normalized normalizedBrowserSessionOptions) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if _, unsafe := normalized.unsafeMethods[strings.ToUpper(ctx.Request.Method)]; !unsafe {
			return
		}

		value, ok := ctx.Get(constants.CtxKeyLoginStatus)
		ls, valid := value.(*auth.LoginStatus)
		if !ok || !valid || ls == nil || ls.State != auth.StateSucc || ls.AuthMode != auth.AuthModeBrowserSession {
			abortAuth(ctx, ls)
			return
		}
		binding, ok := normalized.bindings[ctx.Request.Host]
		if !ok {
			failLoginStatus(ls, auth.ErrInvalidCredential)
			abortAuth(ctx, ls)
			return
		}
		if !validRequestOrigin(ctx, binding.ExternalOrigin) {
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
	}
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
