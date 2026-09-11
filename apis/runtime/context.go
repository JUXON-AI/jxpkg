package runtime

import (
	"net"
	"net/http"
	"strings"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"

	"github.com/JUXON-AI/jxpkg/config"
)

// UserID 从 Gin Context 中获取当前登录用户 ID。
func UserID(ctx *gin.Context) uint {
	return ctx.GetUint(constants.CtxKeyUserID)
}

// UIN 从 Gin Context 中获取当前公司身份 ID。
func UIN(ctx *gin.Context) uint {
	return ctx.GetUint(constants.CtxKeyUIN)
}

// CompanyID 从 Gin Context 中获取当前公司 ID。
func CompanyID(ctx *gin.Context) uint {
	return ctx.GetUint(constants.CtxKeyCompanyID)
}

// MembershipEpoch 从 Gin Context 中获取当前成员身份代次。
func MembershipEpoch(ctx *gin.Context) uint64 {
	return ctx.GetUint64(constants.CtxKeyMembershipEpoch)
}

// LoginWay returns the authentication method carried by the verified request
// principal. Unknown means no complete principal was established.
func LoginWay(ctx *gin.Context) auth.LoginWay {
	ls := loginStatus(ctx)
	if ls.State != auth.StateSucc || ls.Claim == nil {
		return auth.LoginWayUnknown
	}
	return ls.Claim.LoginWay
}

func loginStatus(ctx *gin.Context) *auth.LoginStatus {
	val, _ := ctx.Get(constants.CtxKeyLoginStatus)
	ls, ok := val.(*auth.LoginStatus)
	if !ok {
		return &auth.LoginStatus{}
	}
	return ls
}

// BrowserSessionExpiresAt returns the effective expiry of the verified browser
// Session on the current request. Zero means the route did not establish a
// complete browser Session and callers must fail closed.
func BrowserSessionExpiresAt(ctx *gin.Context) int64 {
	return loginStatus(ctx).BrowserSessionExpiresAt()
}

// RequestID 从 Gin Context 中获取请求 ID。
func RequestID(ctx *gin.Context) string {
	return ctx.GetString(constants.CtxKeyRequestID)
}

// Env 返回配置中的当前环境。
func Env() string {
	return config.Conf().MainConf.Env
}

// GetRealIP 从 HTTP 请求中获取真实客户端 IP。
func GetRealIP(req *http.Request) string {
	ip := req.Header.Get("X-Real-Ip")
	if ip == "" {
		ip = req.Header.Get("X-Forwarded-For")
	}
	if ip == "" {
		ip, _, _ = net.SplitHostPort(req.RemoteAddr)
	}
	if strings.Contains(ip, ",") {
		ip = strings.Split(ip, ",")[0]
	}
	return strings.TrimSpace(ip)
}
