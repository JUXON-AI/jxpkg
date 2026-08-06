package middleware

import (
	"time"

	"github.com/JUXON-AI/jxpkg/config"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CORS returns a middleware that only allows explicitly configured origins.
func CORS(allowedOrigins ...string) gin.HandlerFunc {
	if len(allowedOrigins) == 0 {
		allowedOrigins = config.Conf().MainConf.CORS.AllowedOrigins
	}
	if len(allowedOrigins) == 0 {
		return func(ctx *gin.Context) { ctx.Next() }
	}
	return cors.New(cors.Config{
		AllowOrigins: allowedOrigins,
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowHeaders: []string{
			"Accept", "Origin", "Accept-Encoding", "Accept-Language",
			"Access-Control-Request-Headers", "Access-Control-Request-Method",
			"Host", "Referer", "User-Agent", "Content-Type",
			"Env", "Authorization", "Upgrade", "Connection",
		},
		ExposeHeaders: []string{"Content-Length", "X-Request-Id"},
		MaxAge:        12 * time.Hour,
	})
}
