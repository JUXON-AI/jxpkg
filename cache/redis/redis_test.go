package redis

import "testing"

func TestCacheKeyPrefix(t *testing.T) {
	t.Parallel()
	cache := NewCacheWithPrefix(nil, "account:")
	if got := cache.key("session:1"); got != "account:session:1" {
		t.Fatalf("unexpected prefixed key: %q", got)
	}
}
