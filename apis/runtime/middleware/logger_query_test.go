package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestLoggerRedactsQueryAndPreservesSDKRequestURI(t *testing.T) {
	core, entries := observer.New(zap.InfoLevel)
	wantLevels := make([]zapcore.Level, 0, 2)
	for _, tc := range []struct {
		status int
		level  zapcore.Level
	}{
		{status: http.StatusOK, level: zapcore.InfoLevel},
		{status: http.StatusServiceUnavailable, level: zapcore.ErrorLevel},
	} {
		wantLevels = append(wantLevels, tc.level)
		router := gin.New()
		router.Use(func(c *gin.Context) { logs.SetContextLogger(c, zap.New(core).Sugar()) }, Logger())
		router.GET("/auth/callback", func(c *gin.Context) {
			if c.Request.RequestURI != "/auth/callback?code=secret-code&state=secret-state" {
				t.Error("protocol URI was modified")
			}
			c.Status(tc.status)
		})
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/callback?code=secret-code&state=secret-state", nil))
	}
	if entries.Len() != 2 {
		t.Fatal("missing request logs")
	}
	for i, entry := range entries.All() {
		wantLevel := wantLevels[i]
		if entry.Level != wantLevel {
			t.Fatalf("entry %d level = %s, want %s", i, entry.Level, wantLevel)
		}
		fields := entry.ContextMap()
		if fields["uri"] != "/auth/callback" {
			t.Fatal("query not removed from log")
		}
		for name, value := range fields {
			text := fmt.Sprint(value)
			if strings.Contains(text, "secret-") || strings.Contains(text, "code=") || strings.Contains(text, "state=") {
				t.Fatalf("query value logged in field %q: %q", name, text)
			}
		}
		if strings.Contains(entry.Message, "secret-") || strings.Contains(entry.Message, "code=") || strings.Contains(entry.Message, "state=") {
			t.Fatal("query value logged in message")
		}
	}
}
