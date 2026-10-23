package middleware

import (
	"net/http"

	"github.com/JUXON-AI/jxpkg/apis/runtime"
	"github.com/JUXON-AI/jxpkg/apis/runtime/logtobff"
	"github.com/JUXON-AI/jxpkg/credits"
	"github.com/JUXON-AI/jxpkg/requestid"
	"github.com/gin-gonic/gin"
)

// BindCreditsExecution 在已验证的 Browser Session 之后绑定模型执行，不领取 Key。
// 资源授权仍由业务负责，不能用于匿名、Worker 或兼容 Bearer 路由。
func BindCreditsExecution(client *credits.Client) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if client == nil {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		principal, ok := logtobff.FromContext(ctx.Request.Context())
		if !ok {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		e, err := credits.NewExecution(credits.Subject{OrganizationID: principal.OrganizationID, UserID: principal.UserID}, client.AcquireDefault)
		if err != nil {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		ctx.Set(credits.ExecutionContextKey, e)
		base := requestid.WithContext(ctx.Request.Context(), runtime.RequestID(ctx))
		ctx.Request = ctx.Request.WithContext(credits.WithExecution(base, e))
		ctx.Next()
	}
}
