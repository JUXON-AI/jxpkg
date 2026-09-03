package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
)

// LoginStatus 创建旧版 Bearer 登录态解析中间件。
// Deprecated: 新路由应通过 server.PRequireBearer 或 server.GRequireBearer 显式选择认证模式。
func LoginStatus() gin.HandlerFunc {
	return BearerLoginStatusMiddleware("")
}

func bearerToken(header string) (string, error) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], auth.AuthBearer) || parts[1] == "" {
		return "", fmt.Errorf("%w: authorization header must use Bearer scheme", auth.ErrInvalidCredential)
	}
	return parts[1], nil
}

// AuthMiddleWare 要求上游认证解析和业务注入均成功。
func AuthMiddleWare(ctx *gin.Context) {
	value, ok := ctx.Get(constants.CtxKeyLoginStatus)
	if !ok {
		abortAuth(ctx, nil)
		return
	}
	ls, ok := value.(*auth.LoginStatus)
	if !ok || ls.State != auth.StateSucc {
		abortAuth(ctx, ls)
		return
	}
	ctx.Next()
}

func abortAuth(ctx *gin.Context, ls *auth.LoginStatus) {
	status := http.StatusUnauthorized
	message := "unauthorized"
	if ls != nil && errors.Is(ls.Err, auth.ErrAuthBackendUnavailable) {
		status = http.StatusServiceUnavailable
		message = "authentication service unavailable"
	}
	ctx.Set(constants.CtxKeyCode, status)
	ctx.AbortWithStatusJSON(status, gin.H{"code": status, "message": message})
}

// AuthMiddleWareEmployee 要求上游认证、业务注入和员工角色校验均成功。
func AuthMiddleWareEmployee(ctx *gin.Context) {
	value, ok := ctx.Get(constants.CtxKeyLoginStatus)
	if !ok {
		abortAuth(ctx, nil)
		return
	}
	ls, ok := value.(*auth.LoginStatus)
	if !ok || ls.State != auth.StateSucc || ls.Role != auth.RoleEmployee {
		abortAuth(ctx, ls)
		return
	}
	ctx.Next()
}
