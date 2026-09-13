package redispool

import (
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
)

func TestAccountRedisIsIndependentFromDefaultRedis(t *testing.T) {
	defaultClient := redis.NewClient(&redis.Options{Addr: "default.invalid:6379", DB: 1})
	accountClient := redis.NewClient(&redis.Options{Addr: "account.invalid:6379", DB: 15})
	t.Cleanup(func() {
		_ = defaultClient.Close()
		_ = accountClient.Close()
	})

	redisMu.Lock()
	previousDefault := stdRedis
	previousAccount := accountRedis
	stdRedis = defaultClient
	accountRedis = accountClient
	redisMu.Unlock()
	t.Cleanup(func() {
		redisMu.Lock()
		stdRedis = previousDefault
		accountRedis = previousAccount
		redisMu.Unlock()
	})

	if got := Redis(); got != defaultClient {
		t.Fatalf("Redis() = %p, want default client %p", got, defaultClient)
	}
	if got := Account(); got != accountClient {
		t.Fatalf("Account() = %p, want account client %p", got, accountClient)
	}
	if got := Account().Options().DB; got != 15 {
		t.Fatalf("Account().Options().DB = %d, want 15", got)
	}
	if got := Redis().Options().DB; got != 1 {
		t.Fatalf("Redis().Options().DB = %d, want 1", got)
	}
}

func TestGetAccountRedisBeforeInitialization(t *testing.T) {
	redisMu.Lock()
	previous := accountRedis
	accountRedis = nil
	redisMu.Unlock()
	t.Cleanup(func() {
		redisMu.Lock()
		accountRedis = previous
		redisMu.Unlock()
	})

	client, err := GetAccountRedis()
	if client != nil {
		t.Fatalf("GetAccountRedis() client = %p, want nil", client)
	}
	if err == nil || !strings.Contains(err.Error(), "account redis is nil") {
		t.Fatalf("GetAccountRedis() error = %v, want account redis is nil", err)
	}
}

func TestAccountBeforeInitializationPanics(t *testing.T) {
	redisMu.Lock()
	previous := accountRedis
	accountRedis = nil
	redisMu.Unlock()
	t.Cleanup(func() {
		redisMu.Lock()
		accountRedis = previous
		redisMu.Unlock()
	})

	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("Account() did not panic")
		}
	}()
	Account()
}

func TestConnectRedisRejectsNilConfig(t *testing.T) {
	client, err := connectRedis(nil)
	if client != nil {
		t.Fatalf("connectRedis(nil) client = %p, want nil", client)
	}
	if err == nil || !strings.Contains(err.Error(), "redis config is nil") {
		t.Fatalf("connectRedis(nil) error = %v, want redis config is nil", err)
	}
}
