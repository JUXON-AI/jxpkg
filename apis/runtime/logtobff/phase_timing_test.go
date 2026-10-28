package logtobff

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/JUXON-AI/jxpkg/requestid"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// The diagnostic must preserve trace correlation without inheriting arbitrary sensitive logger fields.
func TestPhaseTimingOnlyEmitsBoundedMetadata(t *testing.T) {
	var (
		path   = filepath.Join(t.TempDir(), "phase.log")
		config = logs.LogsConfig{"default": {{Writer: logs.WriterFile, Encoder: logs.EncoderStandard, Level: zapcore.InfoLevel, Logger: &lumberjack.Logger{Filename: path}}}}
	)
	if err := logs.ReloadConfig("phase-test", config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := logs.ReloadConfig("-", nil); err != nil {
			t.Error(err)
		}
	})
	ctx := requestid.WithContext(context.Background(), "phase-request")
	ctx = logs.WithContextFields(ctx, "authorization", "private-fixture", "cookie", "private-fixture")
	recordIdentityPhase(ctx, "fixed.phase", time.Now())
	recordIdentityPhase(ctx, "fixed.phase", time.Now().Add(-200*time.Millisecond), 3)
	if err := logs.ReloadConfig("-", nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private-fixture") {
		t.Fatal("diagnostic inherited sensitive logger fields")
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("diagnostic entries=%d, want1", len(lines))
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatal(err)
	}
	if entry["msg"] != "logtobff.phase_timing" || entry["phase"] != "fixed.phase" || entry["request_id"] != "phase-request" {
		t.Fatal("diagnostic correlation/phase metadata missing")
	}
	if ms, ok := entry["duration_ms"].(float64); !ok || ms < 200 {
		t.Fatal("diagnostic elapsed time missing")
	}
	if entry["busy_count"] != float64(3) {
		t.Fatal("lease busy count missing")
	}
}
