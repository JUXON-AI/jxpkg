package middleware

import (
	"encoding/hex"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/config"
	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
)

// CustomerHeader 中间件：设置请求 ID 和环境标识到响应头。
func CustomerHeader() gin.HandlerFunc {
	env := config.Conf().MainConf.Env
	return func(ctx *gin.Context) {
		if env == "" {
			return
		}
		reqID := ctx.Request.Header.Get("X-Request-Id")
		if reqID == "" {
			reqID = hex.EncodeToString(uuid.Must(uuid.NewV4(), nil).Bytes())
		}
		ctx.Set(constants.CtxKeyRequestID, reqID)
		ctx.Writer.Header().Set("Env", env)
	}
}
