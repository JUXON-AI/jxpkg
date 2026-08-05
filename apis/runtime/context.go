package runtime

import (
	"net"
	"net/http"
	"strings"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/JUXON-AI/jxpkg/config"
	"github.com/gin-gonic/gin"
)

// Uin 从 Gin Context 中获取当前登录用户 ID。
func Uin(ctx *gin.Context) uint {
	return ctx.GetUint(constants.CtxKeyUin)
}

// LoginStatus 从 Gin Context 中获取当前请求的登录状态。
func LoginStatus(ctx *gin.Context) *auth.LoginStatus {
	val, _ := ctx.Get(constants.CtxKeyLoginStatus)
	ls, ok := val.(*auth.LoginStatus)
	if !ok {
		return &auth.LoginStatus{}
	}
	return ls
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
