package middleware

import (
	"fmt"
	"net/http"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
)

// NewBearerLoginStatusMiddleware 创建仅接受 Bearer Token 的登录态解析中间件。
func NewBearerLoginStatusMiddleware(cookieName string) (gin.HandlerFunc, error) {
	if cookieName != "" {
		if err := validateCookieName(cookieName); err != nil {
			return nil, err
		}
	}
	return bearerLoginStatusMiddleware(cookieName), nil
}

// BearerLoginStatusMiddleware 创建显式 Bearer 路由使用的登录态解析中间件。
func BearerLoginStatusMiddleware(cookieName string) gin.HandlerFunc {
	handler, err := NewBearerLoginStatusMiddleware(cookieName)
	if err != nil {
		return failedLoginStatusMiddleware(auth.AuthModeBearer, err)
	}
	return handler
}

func bearerLoginStatusMiddleware(cookieName string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ls := &auth.LoginStatus{AuthMode: auth.AuthModeBearer}
		ctx.Set(constants.CtxKeyLoginStatus, ls)

		if cookieName != "" && len(matchingCookies(ctx.Request, cookieName)) != 0 {
			failLoginStatus(ls, auth.ErrInvalidCredential)
			return
		}

		authorization := ctx.Request.Header.Values("Authorization")
		if len(authorization) == 0 {
			return
		}
		if len(authorization) != 1 || authorization[0] == "" {
			failLoginStatus(ls, auth.ErrInvalidCredential)
			return
		}

		token, err := bearerToken(authorization[0])
		if err != nil {
			failLoginStatus(ls, err)
			return
		}

		claims, err := auth.ParseToken(token)
		if err != nil {
			failLoginStatus(ls, err)
			return
		}
		ls.State = auth.StateSucc
		ls.Claim = claims
	}
}

func browserBearerMiddleware(bindings map[string]BrowserSessionBinding) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Unbound Hosts have no browser cookie; Bearer authentication still applies.
		binding := bindings[ctx.Request.Host]
		bearerLoginStatusMiddleware(binding.CookieName)(ctx)
	}
}

func failedLoginStatusMiddleware(mode auth.AuthMode, err error) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ls := &auth.LoginStatus{AuthMode: mode}
		failLoginStatus(ls, err)
		ctx.Set(constants.CtxKeyLoginStatus, ls)
	}
}

func failLoginStatus(ls *auth.LoginStatus, err error) {
	ls.Err = err
	ls.State = auth.StateFailed
}

func matchingCookies(request *http.Request, name string) []*http.Cookie {
	matches := make([]*http.Cookie, 0, 1)
	for _, cookie := range request.Cookies() {
		if cookie.Name == name {
			matches = append(matches, cookie)
		}
	}
	return matches
}

func validateCookieName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: cookie name is empty", auth.ErrAuthBackendUnavailable)
	}
	for _, char := range name {
		if char <= 0x20 || char >= 0x7f || char == '(' || char == ')' || char == '<' || char == '>' ||
			char == '@' || char == ',' || char == ';' || char == ':' || char == '\\' || char == '"' ||
			char == '/' || char == '[' || char == ']' || char == '?' || char == '=' || char == '{' || char == '}' {
			return fmt.Errorf("%w: invalid cookie name", auth.ErrAuthBackendUnavailable)
		}
	}
	return nil
}
