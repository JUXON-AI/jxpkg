package logtobff

import (
	"context"
	"errors"
	"testing"

	"github.com/redis/go-redis/v9"
)

func TestSessionRedisSelectsConfiguredIdentityAndDatabase(t *testing.T) {
	cfg := Config{
		Namespace: "test-browser", SessionKey: testOpaque(t), RedisAddress: "unused.invalid:6379",
		RedisUsername: "test-app", RedisPassword: "test-password", RedisDB: 12,
	}
	client, err := NewRedisClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	s, err := newStore(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	if opts := s.db.Options(); opts.Username != "test-app" || opts.DB != 12 {
		t.Fatal("session Redis did not select the configured ACL identity and database")
	}
	if s.prefix != "test-browser:" {
		t.Fatal("session key prefix changed")
	}
}

func TestSessionRedisRejectsIncompleteSharedConfiguration(t *testing.T) {
	for _, cfg := range []Config{{}, {RedisAddress: "unused.invalid:6379", RedisDB: -1}, {RedisAddress: "unused.invalid:6379", RedisUsername: "test-app"}} {
		if _, err := NewRedisClient(cfg); err == nil {
			t.Fatal("accepted invalid session Redis configuration")
		}
	}
}

func TestInjectedSessionRedisOwnership(t *testing.T) {
	backend := loadFixtureRedisConfig(t)
	_, endpoint := fixtureAuthority(t)
	ctx := context.Background()
	cfg := Config{
		Endpoint: endpoint, Origin: "http://localhost:5180", ClientID: "client-one",
		ClientSecret: "fixture-secret", Scopes: []string{"profile"}, CookieName: "session",
		Namespace: "test-browser", RedisAddress: backend.Address, RedisPassword: backend.Password,
		SessionKey: testOpaque(t), Environment: "local", AllowLocalHTTP: true,
	}
	client, err := NewRedisClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	wrong := cfg
	wrong.SessionKey = "invalid"
	if _, err := NewWithRedis(ctx, wrong, client); err == nil {
		t.Fatal("accepted invalid encryption configuration")
	}
	runtime, err := NewWithRedis(ctx, cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.store.db != client {
		t.Fatal("runtime did not use the injected Redis client")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal("constructor failure or runtime shutdown closed caller-owned Redis", err)
	}
	owned, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owned.store.db.Ping(ctx).Err(); !errors.Is(err, redis.ErrClosed) {
		t.Fatal("runtime-owned Redis was not closed", err)
	}
}

func TestInjectedSessionRedisRejectsMismatchedConfig(t *testing.T) {
	cfg := Config{RedisAddress: "redis.example:6379", RedisUsername: "bff-fixture", RedisPassword: "fixture-password", RedisDB: 12}
	client, err := NewRedisClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	if _, err := NewWithRedis(ctx, cfg, nil); err == nil {
		t.Fatal("accepted nil Redis client")
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"address", func(c *Config) { c.RedisAddress = "other.example:6379" }},
		{"username", func(c *Config) { c.RedisUsername = "other" }},
		{"password", func(c *Config) { c.RedisPassword = "other" }},
		{"database", func(c *Config) { c.RedisDB++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrong := cfg
			tc.change(&wrong)
			_, err := NewWithRedis(ctx, wrong, client)
			if err == nil || err.Error() != "session Redis client does not match configuration" {
				t.Fatal("client mismatch was not rejected before identity discovery")
			}
		})
	}
}
