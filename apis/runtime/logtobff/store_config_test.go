package logtobff

import "testing"

func TestSessionRedisSelectsConfiguredIdentityAndDatabase(t *testing.T) {
	s, err := newStore(Config{
		Namespace: "test-browser", SessionKey: testOpaque(t), RedisAddress: "unused.invalid:6379",
		RedisUsername: "test-app", RedisPassword: "test-password", RedisDB: 12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.db.Close(); err != nil {
			t.Error(err)
		}
	})
	if opts := s.db.Options(); opts.Username != "test-app" || opts.DB != 12 {
		t.Fatal("session Redis did not select the configured ACL identity and database")
	}
	if s.prefix != "test-browser:" {
		t.Fatal("session key prefix changed")
	}
}

func TestSessionRedisRejectsIncompleteSharedConfiguration(t *testing.T) {
	for _, cfg := range []Config{{RedisDB: -1}, {RedisUsername: "test-app"}} {
		cfg.SessionKey = testOpaque(t)
		if _, err := newStore(cfg); err == nil {
			t.Fatal("accepted invalid session Redis configuration")
		}
	}
}
