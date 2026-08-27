package verification

import (
	"errors"
	"strings"
	"testing"
)

func TestRedisKeysUseDigests(t *testing.T) {
	destination := "person@example.com"
	clientIP := "192.0.2.1"
	keys := redisKeys("registration", ChannelEmail, destination, clientIP)
	if len(keys) != 4 {
		t.Fatalf("redisKeys() returned %d keys, want 4", len(keys))
	}
	for _, key := range keys {
		if !strings.HasPrefix(key, "core:verification:v1:") {
			t.Fatalf("key %q does not have versioned prefix", key)
		}
		if strings.Contains(key, destination) || strings.Contains(key, clientIP) {
			t.Fatalf("key contains raw destination or IP")
		}
	}
	if !strings.Contains(keys[0], digest(destination)) {
		t.Fatal("challenge key does not contain destination digest")
	}
	if !strings.Contains(keys[3], digest(clientIP)) {
		t.Fatal("IP rate key does not contain IP digest")
	}
}

func TestReserveResultMapping(t *testing.T) {
	tests := []struct {
		// result 表示 Lua 脚本返回值。
		result int64

		// want 表示预期映射的稳定领域错误。
		want error
	}{
		{result: 0},
		{result: 1, want: ErrResendCooldown},
		{result: 2, want: ErrTargetRateLimited},
		{result: 3, want: ErrIPRateLimited},
		{result: 99, want: ErrStore},
	}
	for _, test := range tests {
		err := mapReserveResult(test.result)
		if !errors.Is(err, test.want) {
			t.Fatalf("mapReserveResult(%d) error = %v, want %v", test.result, err, test.want)
		}
	}
}

func TestVerifyResultMapping(t *testing.T) {
	tests := []struct {
		// result 表示 Lua 脚本返回值。
		result int64

		// want 表示预期映射的稳定领域错误。
		want error
	}{
		{result: 0},
		{result: 1, want: ErrChallengeNotFound},
		{result: 2, want: ErrCodeMismatch},
		{result: 3, want: ErrAttemptsExceeded},
		{result: 99, want: ErrStore},
	}
	for _, test := range tests {
		err := mapVerifyResult(test.result)
		if !errors.Is(err, test.want) {
			t.Fatalf("mapVerifyResult(%d) error = %v, want %v", test.result, err, test.want)
		}
	}
}
