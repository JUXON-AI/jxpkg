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

func bearerToken(header string) (string, error) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], auth.AuthBearer) || parts[1] == "" {
		return "", fmt.Errorf("%w: authorization header must use Bearer scheme", auth.ErrInvalidCredential)
	}
	return parts[1], nil
}

// RequireAuthenticated 要求上游认证解析和业务主体发布均成功。
func RequireAuthenticated(ctx *gin.Context) {
	value, ok := ctx.Get(constants.CtxKeyLoginStatus)
	if !ok {
		abortAuth(ctx, nil)
		return
	}
	ls, ok := value.(*auth.LoginStatus)
	if !ok || ls == nil || ls.State != auth.StateSucc {
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
