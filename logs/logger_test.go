package logs

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

func TestLoggerWritesStructuredLogsAndChangesLevel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "default.log")
	reloadFileLogger(t, LogsConfig{
		"default": {
			{
				Writer: WriterConsole,
				Level:  zapcore.InfoLevel,
			},
			fileOutput(path, zapcore.InfoLevel)},
	})

	Debug("hidden")
	Infof("hello %s", "world")
	Errorw("failed", "code", 42)
	SetLevel(zapcore.DebugLevel)
	Debugw("visible", "enabled", true)

	entries := readLogEntries(t, path)
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3: %#v", len(entries), entries)
	}
	if entries[0]["msg"] != "hello world" || entries[0]["module"] != "test" {
		t.Fatalf("unexpected info entry: %#v", entries[0])
	}
	if caller, _ := entries[0]["caller"].(string); !strings.Contains(caller, "logs/logger_test.go") {
		t.Fatalf("unexpected caller %q", caller)
	}
	if entries[1]["code"] != float64(42) || entries[1]["lvl"] != "ERROR" {
		t.Fatalf("unexpected error entry: %#v", entries[1])
	}
	if entries[2]["enabled"] != true || entries[2]["lvl"] != "DEBUG" {
		t.Fatalf("unexpected debug entry: %#v", entries[2])
	}
}

func TestLoggerSupportsNamedAndMultipleOutputs(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.log")
	second := filepath.Join(dir, "second.log")
	worker := filepath.Join(dir, "worker.log")
	reloadFileLogger(t, LogsConfig{
		"default": {
			fileOutput(first, zapcore.InfoLevel),
			fileOutput(second, zapcore.InfoLevel),
		},
		"worker": {fileOutput(worker, zapcore.InfoLevel)},
	})

	Infow("default message", "value", 1)
	Get("worker").Infow("worker message", "value", 2)

	for _, path := range []string{first, second} {
		entries := readLogEntries(t, path)
		if len(entries) != 1 || entries[0]["msg"] != "default message" {
			t.Fatalf("unexpected entries in %s: %#v", path, entries)
		}
	}
	entries := readLogEntries(t, worker)
	if len(entries) != 1 || entries[0]["logger"] != "worker" {
		t.Fatalf("unexpected named logger entry: %#v", entries)
	}
}

func TestInvalidReloadKeepsCurrentLogger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "default.log")
	reloadFileLogger(t, LogsConfig{
		"default": {fileOutput(path, zapcore.InfoLevel)},
	})

	err := ReloadConfig("broken", LogsConfig{
		"default": {{Writer: "unknown", Level: zapcore.InfoLevel}},
	})
	if err == nil {
		t.Fatal("ReloadConfig returned nil for an unsupported writer")
	}
	Info("still active")

	entries := readLogEntries(t, path)
	if len(entries) != 1 || entries[0]["msg"] != "still active" {
		t.Fatalf("current logger was not preserved: %#v", entries)
	}
}

func TestMainLoggerActsAsDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "main.log")
	reloadFileLogger(t, LogsConfig{
		"main": {fileOutput(path, zapcore.InfoLevel)},
	})

	Info("from main")
	entries := readLogEntries(t, path)
	if len(entries) != 1 || entries[0]["logger"] != "main" {
		t.Fatalf("main logger was not used as default: %#v", entries)
	}
}

func TestJSON(t *testing.T) {
	if got := JSON(map[string]int{"answer": 42}); got != `{"answer":42}` {
		t.Fatalf("JSON returned %q", got)
	}
	if got := JSON(make(chan int)); got != "" {
		t.Fatalf("JSON returned %q for an unsupported value", got)
	}
}

func TestIgnorableSyncError(t *testing.T) {
	for _, err := range []error{nil, syscall.EINVAL, syscall.ENOTTY, syscall.EBADF, errors.Join(errors.New("sync"), syscall.EBADF)} {
		if !ignorableSyncError(err) {
			t.Fatalf("ignorableSyncError(%v) = false", err)
		}
	}
	if ignorableSyncError(errors.New("disk failure")) {
		t.Fatal("ignorableSyncError accepted an unrelated error")
	}
}

func reloadFileLogger(t *testing.T, cfg LogsConfig) {
	t.Helper()
	if err := ReloadConfig("test", cfg); err != nil {
		t.Fatalf("ReloadConfig: %v", err)
	}
	t.Cleanup(Close)
}

func fileOutput(path string, level zapcore.Level) LogConfig {
	return LogConfig{
		Writer: WriterFile,
		Level:  level,
		Logger: &lumberjack.Logger{Filename: path},
	}
}

func readLogEntries(t *testing.T, path string) []map[string]interface{} {
	t.Helper()
	if err := Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log %s: %v", path, err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	entries := make([]map[string]interface{}, 0, len(lines))
	for _, line := range lines {
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		entries = append(entries, entry)
	}
	return entries
}
