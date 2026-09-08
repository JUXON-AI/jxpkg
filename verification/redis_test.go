package verification

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
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
		{result: 4, want: ErrChallengeClaimed},
		{result: 99, want: ErrStore},
	}
	for _, test := range tests {
		err := mapVerifyResult(test.result)
		if !errors.Is(err, test.want) {
			t.Fatalf("mapVerifyResult(%d) error = %v, want %v", test.result, err, test.want)
		}
	}
}

func TestClaimMutationResultMapping(t *testing.T) {
	tests := []struct {
		result int64
		want   error
	}{
		{result: 0},
		{result: 1, want: ErrChallengeNotFound},
		{result: 5, want: ErrInvalidClaim},
		{result: 99, want: ErrStore},
	}
	for _, test := range tests {
		err := mapClaimMutationResult(test.result)
		if !errors.Is(err, test.want) {
			t.Fatalf("mapClaimMutationResult(%d) error = %v, want %v", test.result, err, test.want)
		}
	}
}

func TestRedisStoreClaimLifecycle(t *testing.T) {
	address := strings.TrimSpace(os.Getenv("JXPKG_TEST_REDIS_ADDR"))
	if address == "" {
		t.Skip("JXPKG_TEST_REDIS_ADDR is required for Redis integration tests")
	}
	client := redis.NewClient(&redis.Options{Addr: address})
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("connect to isolated test Redis: %v", err)
	}
	store, err := NewRedisStore(client)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, &fakeDeliverer{}, validPolicy())
	if err != nil {
		t.Fatal(err)
	}
	policy := validPolicy()
	policy.CodeTTL = 10 * time.Second
	policy.ResendCooldown = time.Second
	unique := time.Now().UnixNano()
	sendInput := SendInput{
		Purpose:     "registration",
		Channel:     ChannelEmail,
		Destination: fmt.Sprintf("claim-%d@example.com", unique),
		ClientIP:    "192.0.2.1",
	}
	verifyInput := VerifyInput{
		Purpose:     sendInput.Purpose,
		Channel:     sendInput.Channel,
		Destination: sendInput.Destination,
		Code:        "123456",
	}
	keys := redisKeys(sendInput.Purpose, sendInput.Channel, sendInput.Destination, sendInput.ClientIP)
	t.Cleanup(func() { _ = client.Del(context.Background(), keys...).Err() })
	if err := store.Reserve(ctx, sendInput, verifyInput.Code, policy); err != nil {
		t.Fatal(err)
	}
	key := challengeKey(sendInput.Purpose, sendInput.Channel, sendInput.Destination)
	initialTTL, err := client.PTTL(ctx, key).Result()
	if err != nil {
		t.Fatal(err)
	}

	claim, err := service.VerifyAndClaim(ctx, verifyInput)
	if err != nil {
		t.Fatal(err)
	}
	claimedTTL, err := client.PTTL(ctx, key).Result()
	if err != nil {
		t.Fatal(err)
	}
	if claimedTTL <= initialTTL-500*time.Millisecond || claimedTTL > initialTTL {
		t.Fatalf("TTL after claim = %v, want preserved near %v", claimedTTL, initialTTL)
	}
	if _, err := service.VerifyAndClaim(ctx, verifyInput); !errors.Is(err, ErrChallengeClaimed) {
		t.Fatalf("concurrent VerifyAndClaim() error = %v, want ErrChallengeClaimed", err)
	}
	if err := service.VerifyAndConsume(ctx, verifyInput); !errors.Is(err, ErrChallengeClaimed) {
		t.Fatalf("VerifyAndConsume() during claim error = %v, want ErrChallengeClaimed", err)
	}

	time.Sleep(policy.ResendCooldown + 100*time.Millisecond)
	if err := store.Reserve(ctx, sendInput, "654321", policy); !errors.Is(err, ErrResendCooldown) {
		t.Fatalf("Reserve() during claim error = %v, want ErrResendCooldown", err)
	}
	if err := service.ReleaseClaim(ctx, claim); err != nil {
		t.Fatal(err)
	}
	releasedTTL, err := client.PTTL(ctx, key).Result()
	if err != nil {
		t.Fatal(err)
	}
	if releasedTTL >= initialTTL || releasedTTL <= 0 {
		t.Fatalf("TTL after release = %v, want remaining original TTL below %v", releasedTTL, initialTTL)
	}

	claim, err = service.VerifyAndClaim(ctx, verifyInput)
	if err != nil {
		t.Fatalf("VerifyAndClaim() after release error = %v", err)
	}
	if err := service.ConsumeClaim(ctx, claim); err != nil {
		t.Fatal(err)
	}
	if exists, err := client.Exists(ctx, key).Result(); err != nil || exists != 0 {
		t.Fatal("challenge still exists after ConsumeClaim()")
	}
	if err := service.ConsumeClaim(ctx, claim); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("replayed ConsumeClaim() error = %v, want ErrChallengeNotFound", err)
	}
}
