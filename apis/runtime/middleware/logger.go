package middleware

import (
	"fmt"
	"strings"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	grt "github.com/JUXON-AI/jxpkg/apis/runtime"
	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/gin-gonic/gin"
)

// Logger 请求日志中间件，记录方法和响应码等信息。
// whitelist 中可指定不记录日志的路径后缀（如健康检查接口）。
func Logger(whitelist ...string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		reqid := ctx.GetString(constants.CtxKeyRequestID)
		logs.SetContextFields(ctx, "reqid", reqid)

		currReq := ctx.FullPath()
		for _, w := range whitelist {
			if strings.HasSuffix(currReq, w) {
				ctx.Next()
				return
			}
		}

		start := time.Now()
		ctx.Next()
		cost := time.Since(start)

		if ctx.Writer.Status() >= 500 {
			logs.LoggerFromContext(ctx).Errorw(fmt.Sprint(ctx.Writer.Status()),
				"method", ctx.Request.Method,
				"uri", requestLogURI(ctx),
				"latency", fmt.Sprintf("%.3f", cost.Seconds()),
				"clientip", grt.GetRealIP(ctx.Request),
			)
		} else {
			code := ctx.GetInt(constants.CtxKeyCode)
			logs.LoggerFromContext(ctx).Infow(fmt.Sprint(code),
				"method", ctx.Request.Method,
				"uri", requestLogURI(ctx),
				"latency", fmt.Sprintf("%.3f", cost.Seconds()),
				"clientip", grt.GetRealIP(ctx.Request),
			)
		}
	}
}

func requestLogURI(ctx *gin.Context) string {
	if route := ctx.FullPath(); route != "" {
		return route
	}
	if ctx.Request == nil || ctx.Request.URL == nil {
		return ""
	}
	return ctx.Request.URL.Path
}
