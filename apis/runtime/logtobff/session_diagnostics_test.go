package logtobff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/JUXON-AI/jxpkg/requestid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// TestIdentityRedisFailureDiagnostic 验证真实拨号失败经过会话拒绝边界后保留原因分类且不泄密。
func TestIdentityRedisFailureDiagnostic(t *testing.T) {
	for _, tt := range []struct{ name, resource, reason string }{
		{name: "identity", reason: "session_unavailable"},
		{name: "resource", resource: "https://resource.invalid", reason: "session_store_unavailable"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assertSessionRedisFailureDiagnostic(t, tt.resource, tt.reason)
		})
	}
}

// assertSessionRedisFailureDiagnostic 验证两种会话模式沿用原响应并输出相同脱敏诊断。
func assertSessionRedisFailureDiagnostic(t *testing.T, resource, reason string) {
	t.Helper()
	path := captureSessionDiagnostics(t)
	private := "private-redis-fixture"
	cause := &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 6379}, Err: fmt.Errorf("%s: %w", private, syscall.ECONNREFUSED)}
	client := redis.NewClient(&redis.Options{
		Addr: "unused.invalid:6379", MaxRetries: -1,
		Dialer: func(context.Context, string, string) (net.Conn, error) { return nil, cause },
	})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	s, err := newStore(Config{SessionKey: testOpaque(t), Namespace: "private-prefix"}, client)
	if err != nil {
		t.Fatal(err)
	}
	a := &Runtime{store: s, config: Config{Origin: "http://localhost:5180", CookieName: "session", APIResource: resource}}
	r := httptest.NewRequest(http.MethodGet, "http://localhost:5180/auth/session", nil)
	sessionID := testOpaque(t)
	r.AddCookie(&http.Cookie{Name: "session", Value: sessionID})
	ctx := requestid.WithContext(r.Context(), "redis-failure-request")
	ctx = logs.WithContextFields(ctx, "cookie", private, "authorization", private)
	w := httptest.NewRecorder()
	a.withSession(func(*http.Request, *session) result {
		t.Error("unavailable session reached identity authority")
		return result{}
	})(w, r.WithContext(ctx))
	if w.Code != http.StatusServiceUnavailable || w.Body.String() != "{\"error\":\""+reason+"\"}\n" {
		t.Fatalf("changed rejection contract: status=%d body=%s", w.Code, w.Body.String())
	}
	entries := readSessionDiagnostics(t, path, sessionID, s.prefix+"s:"+sessionID, s.prefix+"lock:"+sessionID)
	rejected, released := 0, 0
	for _, entry := range entries {
		if entry["msg"] == "logtobff.session_lease.release_failed" {
			released++
			if entry["redis_operation"] != "lease_release" || entry["request_id"] != "redis-failure-request" || entry["failure_kind"] != "connection_refused" {
				t.Errorf("cleanup failure diagnostic incomplete: %v", entry)
			}
		}
		if entry["msg"] != "logtobff.request.rejected" {
			continue
		}
		rejected++
		for key, want := range map[string]any{
			"request_id": "redis-failure-request", "reason": reason,
			"dependency": "redis", "redis_operation": "lease_acquire",
			"failure_kind": "connection_refused", "network_operation": "dial",
			"status": float64(503), "pool_total_conns": float64(0),
		} {
			if entry[key] != want {
				t.Errorf("diagnostic %s=%v, want %v", key, entry[key], want)
			}
		}
	}
	if rejected != 1 || released != 1 {
		t.Fatalf("rejection entries=%d cleanup entries=%d, want1 each", rejected, released)
	}
	// 提交也必须保留错误链和失败快照，不能只覆盖获取租约。
	err = s.commit(ctx, testOpaque(t), testOpaque(t), testOpaque(t), renewalPolicySession(time.Now()), false)
	var failure *sessionRedisError
	if !errors.Is(err, cause) || !errors.As(err, &failure) || failure.operation != "lease_commit" {
		t.Fatalf("commit lost Redis cause or operation: %v", err)
	}
}

// TestSessionFailureKinds 验证可恢复故障分类和错误链，不依赖真实 Redis。
func TestSessionFailureKinds(t *testing.T) {
	tests := []struct {
		name, kind, operation string
		err                   error
	}{
		{name: "pool timeout", kind: "pool_timeout", err: redis.ErrPoolTimeout},
		{name: "pool exhausted", kind: "pool_exhausted", err: redis.ErrPoolExhausted},
		{name: "canceled", kind: "context_canceled", err: context.Canceled},
		{name: "deadline", kind: "context_deadline", err: context.DeadlineExceeded},
		{name: "read timeout", kind: "network_timeout", operation: "read", err: &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}},
		{name: "write reset", kind: "connection_reset", operation: "write", err: &net.OpError{Op: "write", Err: syscall.ECONNRESET}},
		{name: "closed", kind: "connection_closed", err: io.EOF},
		{name: "partial reply", kind: "connection_closed", err: io.ErrUnexpectedEOF},
		{name: "unknown network operation", kind: "connection_refused", operation: "other", err: &net.OpError{Op: "private-redis-fixture", Err: syscall.ECONNREFUSED}},
		{name: "network error", kind: "network_error", operation: "read", err: &net.OpError{Op: "read", Err: errors.New("private-redis-fixture")}},
		{name: "server error", kind: "redis_server_error", err: sessionDiagnosticServerError("private-redis-fixture")},
		{name: "missing", kind: "session_missing", err: _errMissing},
		{name: "busy", kind: "session_busy", err: _errBusy},
		{name: "invalid", kind: "session_invalid", err: _errInvalid},
		{name: "unknown", kind: "unknown", err: errors.New("private-redis-fixture")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := fmt.Errorf("outer: %w", tt.err)
			fields := sessionFailureFields(wrapped)
			got := make(map[string]any, len(fields)/2)
			for i := 0; i < len(fields); i += 2 {
				got[fields[i].(string)] = fields[i+1]
			}
			if got["failure_kind"] != tt.kind || got["network_operation"] != tt.operation {
				t.Fatalf("kind=%v operation=%v, want %s/%s", got["failure_kind"], got["network_operation"], tt.kind, tt.operation)
			}
			failure := &sessionRedisError{cause: wrapped, operation: "lease_commit", elapsed: 1200 * time.Millisecond, pool: redis.PoolStats{TotalConns: 8, IdleConns: 0, Timeouts: 3}}
			if !errors.Is(failure, tt.err) {
				t.Fatal("diagnostic wrapper lost original error matching")
			}
			if failure.Error() != "authentication Redis operation failed" {
				t.Fatal("diagnostic wrapper exposed an upstream error")
			}
			fields = sessionFailureFields(failure)
			got = make(map[string]any, len(fields)/2)
			for i := 0; i < len(fields); i += 2 {
				got[fields[i].(string)] = fields[i+1]
			}
			if got["elapsed_ms"] != int64(1200) || got["pool_total_conns"] != uint32(8) || got["pool_timeouts_total"] != uint32(3) || got["redis_operation"] != "lease_commit" {
				t.Fatalf("Redis failure snapshot missing: %v", got)
			}
		})
	}
}

type sessionDiagnosticServerError string

func (e sessionDiagnosticServerError) Error() string { return string(e) }

func (sessionDiagnosticServerError) RedisError() {}

// captureSessionDiagnostics 隔离全局日志配置；本文件测试不能并行。
func captureSessionDiagnostics(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session.log")
	config := logs.LogsConfig{"default": {{Writer: logs.WriterFile, Encoder: logs.EncoderStandard, Level: zapcore.InfoLevel, Logger: &lumberjack.Logger{Filename: path}}}}
	if err := logs.ReloadConfig("session-test", config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := logs.ReloadConfig("-", nil); err != nil {
			t.Error(err)
		}
	})
	return path
}

// readSessionDiagnostics 读取脱敏诊断并拒绝凭据、地址和任意上下文字段泄漏。
func readSessionDiagnostics(t *testing.T, path string, forbiddenValues ...string) []map[string]any {
	t.Helper()
	if err := logs.ReloadConfig("-", nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range append(forbiddenValues, "private-redis-fixture", "unused.invalid", "192.0.2.1", "private-prefix", "authorization", "cookie") {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("diagnostic leaked %s", forbidden)
		}
	}
	var entries []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	return entries
}
