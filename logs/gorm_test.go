package logs

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestGormLoggerHonorsModesAndContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gorm.log")
	reloadFileLogger(t, LogsConfig{
		"gorm": {fileOutput(path, zapcore.DebugLevel)},
	})

	ctx := WithContextFields(context.Background(), "request_id", "req-db")
	l := GetGorm("gorm")
	l.Trace(ctx, time.Now(), func() (string, int64) {
		return "SELECT 1", 1
	}, nil)
	l.Trace(ctx, time.Now(), func() (string, int64) {
		return "SELECT broken", 0
	}, errors.New("query failed"))
	l.LogMode(gormlogger.Warn).Trace(ctx, time.Now().Add(-time.Second), func() (string, int64) {
		return "SELECT slow", 3
	}, nil)

	called := false
	l.LogMode(gormlogger.Silent).Trace(ctx, time.Now(), func() (string, int64) {
		called = true
		return "SELECT hidden", 0
	}, nil)
	if called {
		t.Fatal("Silent mode evaluated the SQL callback")
	}

	entries := readLogEntries(t, path)
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3: %#v", len(entries), entries)
	}
	if entries[0]["lvl"] != "INFO" || entries[0]["request_id"] != "req-db" || entries[0]["rows"] != float64(1) {
		t.Fatalf("unexpected normal query entry: %#v", entries[0])
	}
	if entries[1]["lvl"] != "ERROR" || entries[1]["error"] != "query failed" {
		t.Fatalf("unexpected failed query entry: %#v", entries[1])
	}
	if entries[2]["lvl"] != "WARN" || entries[2]["slow"] != true {
		t.Fatalf("unexpected slow query entry: %#v", entries[2])
	}
}

func TestGormLogMethodsHonorMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gorm-level.log")
	reloadFileLogger(t, LogsConfig{
		"gorm": {fileOutput(path, zapcore.DebugLevel)},
	})

	l := GetGorm("gorm").LogMode(gormlogger.Error)
	l.Info(context.Background(), "hidden info")
	l.Warn(context.Background(), "hidden warning")
	l.Error(context.Background(), "visible error")

	entries := readLogEntries(t, path)
	if len(entries) != 1 || entries[0]["msg"] != "visible error" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}

func TestGormLoggerFiltersParams(t *testing.T) {
	filter := GetGorm("gorm").(gorm.ParamsFilter)
	sql, params := filter.ParamsFilter(context.Background(), "INSERT INTO users(password) VALUES (?)", "secret")
	if sql != "INSERT INTO users(password) VALUES (?)" {
		t.Fatalf("SQL = %q, want placeholders preserved", sql)
	}
	if len(params) != 0 {
		t.Fatalf("params = %#v, want no logged parameters", params)
	}
}
