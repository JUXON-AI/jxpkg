package middleware

import (
	"fmt"
	"strings"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/errcode"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func LoginStatus() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			authstr = ctx.Request.Header.Get("Authorization")
			ls      = &auth.LoginStatus{}
		)
		defer func() {
			ctx.Set(constants.CtxKeyLoginStatus, ls)
			if ls.Claim != nil && ls.Claim.Uin > 0 {
				ctx.Set(constants.CtxKeyUin, ls.Claim.Uin)
			}
		}()
		if authstr == "" {
			return
		}

		authstr = strings.TrimPrefix(authstr, auth.AuthBearer)
		authstr = strings.TrimSpace(authstr)
		ls.Token = authstr

		if strings.HasPrefix(authstr, auth.AuthAPIKeyPrefix) {
			ls.Role = auth.RoleAPI
			ls.State = auth.StateSucc
			ls.Claim = new(auth.UserClaims)
			return
		}

		claims := new(auth.UserClaims)
		_, err := jwt.ParseWithClaims(ls.Token, claims, func(token *jwt.Token) (interface{}, error) {
			if token.Claims == nil {
				return nil, fmt.Errorf("token claims is nil")
			}
			c, ok := token.Claims.(*auth.UserClaims)
			if !ok {
				return nil, fmt.Errorf("token claims is not UserClaims")
			}
			return auth.GetJwtSecret(c.Issuer)
		})
		if err != nil {
			logs.Warnw("[auth] parse claims failed.", "error", err, "token", ls.Token)
			ls.Err = err
			ls.State = auth.StateFailed
			return
		}
		ls.State = auth.StateSucc
		ls.Claim = claims
	}
}

func AuthMiddleWare(ctx *gin.Context) {
	val, ok := ctx.Get(constants.CtxKeyLoginStatus)
	if !ok {
		ctx.AbortWithStatusJSON(errcode.ErrCode_Unauthorized, gin.H{"code": errcode.ErrCode_Unauthorized, "message": "unauthorized"})
		return
	}
	ls, ok := val.(*auth.LoginStatus)
	if !ok || ls.State != auth.StateSucc {
		ctx.AbortWithStatusJSON(errcode.ErrCode_Unauthorized, gin.H{"code": errcode.ErrCode_Unauthorized, "message": "unauthorized"})
		return
	}
	ctx.Next()
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
