package safeerror

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestWrapPreservesClassificationAndSafeOuterText(t *testing.T) {
	cause := &url.Error{Op: "Post", URL: "https://user:PRIVATE_PASSWORD@private.example", Err: context.DeadlineExceeded}
	err := Wrap("operation unavailable", cause)
	var parsed *url.Error
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &parsed) || parsed != cause {
		t.Fatal("cause classification lost")
	}
	if outer := fmt.Errorf("caller: %w", err); strings.Contains(outer.Error(), "PRIVATE") || strings.Contains(outer.Error(), "private.example") || outer.Error() != "caller: operation unavailable" {
		t.Fatal("outer message exposed private cause")
	}
	if Wrap("operation unavailable", nil) != nil {
		t.Fatal("nil cause became an error")
	}
}
