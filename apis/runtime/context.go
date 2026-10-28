package runtime

import (
	"net"
	"net/http"
	"strings"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/gin-gonic/gin"

	"github.com/JUXON-AI/jxpkg/config"
)

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
