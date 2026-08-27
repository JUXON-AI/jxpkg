package logs

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap/zapcore"
)

func TestStandardContextFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "context.log")
	reloadFileLogger(t, LogsConfig{
		"default": {fileOutput(path, zapcore.InfoLevel)},
	})

	ctx := WithContextFields(context.Background(), "request_id", "req-1")
	ctx = WithContextFields(ctx, "user_id", 7)
	InfoContextw(ctx, "context message", "result", "ok")

	entries := readLogEntries(t, path)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	entry := entries[0]
	if entry["request_id"] != "req-1" || entry["user_id"] != float64(7) || entry["result"] != "ok" {
		t.Fatalf("context fields missing: %#v", entry)
	}
}

func TestGinContextFieldsAndLogger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gin.log")
	reloadFileLogger(t, LogsConfig{
		"default": {fileOutput(path, zapcore.InfoLevel)},
	})

	gctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	SetContextFields(gctx, "request_id", "req-2")
	SetContextFields(gctx, "route", "/users/:id")
	SetContextLogger(gctx, Named("http"))
	InfoContext(gctx, "gin message")

	entries := readLogEntries(t, path)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	entry := entries[0]
	if entry["request_id"] != "req-2" || entry["route"] != "/users/:id" || entry["mod"] != "http" {
		t.Fatalf("Gin context logger missing data: %#v", entry)
	}
}

func TestNilContextFallsBackToDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nil.log")
	reloadFileLogger(t, LogsConfig{
		"default": {fileOutput(path, zapcore.InfoLevel)},
	})

	InfoContext(nil, "nil context")
	entries := readLogEntries(t, path)
	if len(entries) != 1 || entries[0]["msg"] != "nil context" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}
