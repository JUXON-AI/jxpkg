package middleware

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CORS 返回允许所有来源的 CORS 中间件。
func CORS() gin.HandlerFunc {
	return cors.New(cors.Config{
		AllowAllOrigins: true,
		AllowMethods:    []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
		AllowHeaders: []string{
			"Accept", "Origin", "Accept-Encoding", "Accept-Language",
			"Access-Control-Request-Headers", "Access-Control-Request-Method",
			"Host", "Referer", "User-Agent", "Content-Type",
			"Env", "Authorization", "Upgrade", "Connection",
		},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	})
}
