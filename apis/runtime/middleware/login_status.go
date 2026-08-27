package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/errcode"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
)

func LoginStatus() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			authstr = ctx.Request.Header.Get("Authorization")
			ls      = &auth.LoginStatus{}
		)
		defer func() {
			ctx.Set(constants.CtxKeyLoginStatus, ls)
		}()
		if authstr == "" {
			return
		}

		token, err := bearerToken(authstr)
		if err != nil {
			ls.Err = err
			ls.State = auth.StateFailed
			return
		}

		claims, err := auth.ParseToken(token)
		if err != nil {
			ls.Err = err
			ls.State = auth.StateFailed
			return
		}
		ls.State = auth.StateSucc
		ls.Claim = claims
	}
}

func bearerToken(header string) (string, error) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], auth.AuthBearer) || parts[1] == "" {
		return "", fmt.Errorf("%w: authorization header must use Bearer scheme", auth.ErrInvalidCredential)
	}
	return parts[1], nil
}

func AuthMiddleWare(ctx *gin.Context) {
	val, ok := ctx.Get(constants.CtxKeyLoginStatus)
	if !ok {
		abortAuth(ctx, nil)
		return
	}
	ls, ok := val.(*auth.LoginStatus)
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

func AuthMiddleWareEmployee(ctx *gin.Context) {
	val, ok := ctx.Get(constants.CtxKeyLoginStatus)
	if !ok {
		ctx.AbortWithStatusJSON(errcode.ErrCode_Unauthorized, gin.H{"code": errcode.ErrCode_Unauthorized, "message": "unauthorized"})
		return
	}
	ls, ok := val.(*auth.LoginStatus)
	if !ok || ls.State != auth.StateSucc || ls.Role != auth.RoleEmployee {
		ctx.AbortWithStatusJSON(errcode.ErrCode_Unauthorized, gin.H{"code": errcode.ErrCode_Unauthorized, "message": "unauthorized"})
		return
	}
	ctx.Next()
}
