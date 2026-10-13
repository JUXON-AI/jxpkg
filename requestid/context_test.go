package requestid

import (
	"context"
	"strings"
	"testing"
)

func TestContextAndInputBoundaries(t *testing.T) {
	for _, id := range []string{"req-123", "a_b.c", strings.Repeat("x", 128)} {
		if got := FromContext(WithContext(context.Background(), id)); got != id {
			t.Fatal("lost request ID")
		}
	}
	for _, id := range []string{"", "bad\nheader", "space id", strings.Repeat("x", 129)} {
		if Valid(id) || FromContext(WithContext(context.Background(), id)) != "" {
			t.Fatal("unsafe ID accepted")
		}
	}
	if FromContext(context.WithValue(context.Background(), "reqid", "legacy-id")) != "legacy-id" || FromContext(nil) != "" {
		t.Fatal("legacy context mismatch")
	}
}
