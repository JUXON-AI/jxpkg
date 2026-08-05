package middleware

import (
	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/gin-gonic/gin"
)

// AcceptLanguage 中间件：从请求头中提取 Accept-Language 存入上下文。
func AcceptLanguage() gin.HandlerFunc {
	return func(c *gin.Context) {
		acceptLang := c.Request.Header.Get("Accept-Language")
		c.Set(constants.CtxKeyLang, acceptLang)
	}
}
