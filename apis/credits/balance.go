// Package credits 装配共享额度协议的浏览器接口，不依赖业务应用。
package credits

import (
	"errors"
	"strings"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/apiobj"
	"github.com/JUXON-AI/jxpkg/apis/errcode"
	"github.com/JUXON-AI/jxpkg/apis/runtime"
	"github.com/JUXON-AI/jxpkg/apis/runtime/server"
	clientcredits "github.com/JUXON-AI/jxpkg/credits"
	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/JUXON-AI/jxpkg/requestid"
	"github.com/gin-gonic/gin"
)

// GetMyModelBalanceRequest 不接收员工身份，主体只能来自验证后的 Session。
type GetMyModelBalanceRequest struct {
	// BaseRequest 是 JX 请求信封。
	apiobj.BaseRequest
	// Request 是无参数业务输入。
	Request struct{} `json:"request"`
}

// GetMyModelBalanceResponse 是不包含凭据的 JX 余额响应。
type GetMyModelBalanceResponse struct {
	// BaseResponse 提供错误码与关联 ID。
	apiobj.BaseResponse
	// Response 保留远端原始单位。
	Response BrowserBalance `json:"response"`
}

// BrowserBalance 回传已验证的主体，使客户端能够拒绝身份切换时的迟到响应。
type BrowserBalance struct {
	// Balance 是原始 wallet 快照。
	clientcredits.Balance
	// CompanyID 来自当前已验证 Session，不来自请求。
	CompanyID uint `json:"company_id"`
	// UIN 来自当前已验证 Session，不来自请求。
	UIN uint `json:"uin"`
}

// RegisterBrowserBalance 在业务域注册 Session/组织校验/CSRF 保护的余额接口。
// 该协议供 JXX 与后续应用共用，避免每个业务重复身份提取及错误映射。
func RegisterBrowserBalance(router *server.Router, service string, client *clientcredits.Client) error {
	if router == nil || client == nil || service == "" || len(service) > 64 || strings.Trim(service, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
		return clientcredits.ErrUnavailable
	}
	router.PRequireAuthorizedBrowserSession(service+".GetMyModelBalance", nil, balanceHandler(client))
	return nil
}

func balanceHandler(client *clientcredits.Client) func(*gin.Context, *GetMyModelBalanceRequest, *GetMyModelBalanceResponse) {
	return func(ctx *gin.Context, _ *GetMyModelBalanceRequest, resp *GetMyModelBalanceResponse) {
		ctx.Header("Cache-Control", "no-store")
		ctx.Header("Pragma", "no-cache")
		if runtime.UserID(ctx) == 0 || runtime.CompanyID(ctx) == 0 || runtime.UIN(ctx) == 0 || runtime.MembershipEpoch(ctx) == 0 || runtime.BrowserSessionExpiresAt(ctx) <= time.Now().Unix() {
			resp.Code, resp.Message = errcode.ErrCode_NoPermission, "当前身份不可查询额度"
			return
		}
		base := requestid.WithContext(ctx.Request.Context(), runtime.RequestID(ctx))
		balance, err := client.GetBalance(base, clientcredits.Subject{CompanyID: runtime.CompanyID(ctx), UIN: runtime.UIN(ctx)})
		if err != nil {
			resp.Code, resp.Message = errcode.ErrCode_ServiceUnavailable, "额度服务暂时不可用"
			if errors.Is(err, clientcredits.ErrDenied) {
				resp.Code, resp.Message = errcode.ErrCode_NoPermission, "当前身份不可查询额度"
			}
			logs.WarnContextw(base, "credits.browser.balance.failed", "code", resp.Code)
			return
		}
		resp.Response = BrowserBalance{Balance: balance, CompanyID: runtime.CompanyID(ctx), UIN: runtime.UIN(ctx)}
	}
}
