package middleware

import (
	"fmt"
	"strings"
	"time"

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

		if !strings.HasPrefix(authstr, auth.AuthBearer) {
			ls.Err = fmt.Errorf("unsupported authorization scheme")
			ls.State = auth.StateFailed
			return
		}

		authstr = strings.TrimSpace(strings.TrimPrefix(authstr, auth.AuthBearer))
		if authstr == "" {
			ls.Err = fmt.Errorf("bearer token is empty")
			ls.State = auth.StateFailed
			return
		}
		ls.Token = authstr

		claims := new(auth.UserClaims)
		var expectedAudience string
		token, err := jwt.ParseWithClaims(ls.Token, claims, func(token *jwt.Token) (interface{}, error) {
			if token.Claims == nil {
				return nil, fmt.Errorf("token claims is nil")
			}
			c, ok := token.Claims.(*auth.UserClaims)
			if !ok {
				return nil, fmt.Errorf("token claims is not UserClaims")
			}
			if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, fmt.Errorf("unexpected jwt signing method")
			}
			secret, audience, err := auth.GetJWTVerification(c.Issuer)
			if err != nil {
				return nil, err
			}
			expectedAudience = audience
			return secret, nil
		},
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithLeeway(30*time.Second),
		)
		if err != nil {
			logs.Warnw("[auth] parse claims failed.", "error", err)
			ls.Err = err
			ls.State = auth.StateFailed
			return
		}
		if token == nil || !token.Valid {
			ls.Err = fmt.Errorf("token is invalid")
			ls.State = auth.StateFailed
			return
		}
		if claims.Audience != expectedAudience {
			ls.Err = fmt.Errorf("token audience is invalid")
			ls.State = auth.StateFailed
			return
		}
		ls.State = auth.StateSucc
		ls.Role = auth.RoleUser
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
