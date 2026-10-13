package middleware

import (
	"net/http"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/runtime"
	"github.com/JUXON-AI/jxpkg/credits"
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
		if runtime.UserID(ctx) == 0 || runtime.CompanyID(ctx) == 0 || runtime.UIN(ctx) == 0 || runtime.MembershipEpoch(ctx) == 0 || runtime.BrowserSessionExpiresAt(ctx) <= time.Now().Unix() {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		e, err := credits.NewExecution(credits.Subject{CompanyID: runtime.CompanyID(ctx), UIN: runtime.UIN(ctx)}, client.AcquireDefault)
		if err != nil {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		ctx.Set(credits.ExecutionContextKey, e)
		ctx.Request = ctx.Request.WithContext(credits.WithExecution(ctx.Request.Context(), e))
		ctx.Next()
	}
}
