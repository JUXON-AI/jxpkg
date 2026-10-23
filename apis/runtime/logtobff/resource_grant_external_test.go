package logtobff_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/runtime/logtobff"
)

type forgedCapabilityContext struct{}

// Deadline reports no fixed deadline for the forged context fixture.
func (forgedCapabilityContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done reports that the forged context cannot be cancelled.
func (forgedCapabilityContext) Done() <-chan struct{} { return nil }

// Err reports that the forged context has no cancellation error.
func (forgedCapabilityContext) Err() error { return nil }

// Value deliberately returns the obsolete public function shape for every key.
func (forgedCapabilityContext) Value(any) any {
	return func(context.Context, string, string) error { return nil }
}

// TestRevokeResourceGrantRejectsExternalFunctionForgery verifies an external
// caller cannot satisfy the private revocation capability with a bare function.
func TestRevokeResourceGrantRejectsExternalFunctionForgery(t *testing.T) {
	var ctx forgedCapabilityContext
	if err := logtobff.RevokeResourceGrant(ctx, "https://hub.invalid/mcp", "grant-one"); !errors.Is(err, logtobff.ErrAuthorizationChanged) {
		t.Fatalf("forged capability error = %v", err)
	}
}
