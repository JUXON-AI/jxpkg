package middleware

import (
	"bytes"
	"encoding/json"
	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/JUXON-AI/jxpkg/requestid"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestIDFlowsThroughStandardContextAndLogs(t *testing.T) {
	var buffer bytes.Buffer
	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&buffer), zap.InfoLevel)
	engine := gin.New()
	engine.Use(func(ctx *gin.Context) {
		ctx.Request = ctx.Request.WithContext(logs.WithContextLogger(ctx.Request.Context(), zap.New(core).Sugar()))
	}, CustomerHeader(), Logger())
	engine.POST("/task", func(ctx *gin.Context) {
		if requestid.FromContext(ctx.Request.Context()) != "original-request" {
			t.Error("lost standard Context ID")
		}
		logs.InfoContext(ctx.Request.Context(), "test.task.phase")
		ctx.Status(204)
	})
	r := httptest.NewRequest(http.MethodPost, "/task", nil)
	r.Header.Set("X-Request-Id", "original-request")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, r)
	if w.Code != 204 || w.Header().Get("X-Request-Id") != "original-request" {
		t.Fatal("wrong response trace")
	}
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buffer.Bytes()), &entry); err != nil {
		t.Fatal(err)
	}
	if entry["msg"] != "test.task.phase" || entry["reqid"] != "original-request" {
		t.Fatal("standard Context log lost ID")
	}
}
