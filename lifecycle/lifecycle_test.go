package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestShutdownCancelsContextAndClosesInReverseOrder(t *testing.T) {
	t.Parallel()
	lifecycle := New()
	var order []int
	lifecycle.AddCloseFunc(func() error {
		order = append(order, 1)
		return nil
	})
	lifecycle.AddCloseFunc(func() error {
		order = append(order, 2)
		return nil
	})

	if err := lifecycle.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
	if lifecycle.Context().Err() == nil {
		t.Fatal("lifecycle context was not canceled")
	}
	if !reflect.DeepEqual(order, []int{2, 1}) {
		t.Fatalf("unexpected close order: %v", order)
	}
}

func TestShutdownReturnsCloserErrors(t *testing.T) {
	t.Parallel()
	lifecycle := New()
	want := errors.New("close failed")
	lifecycle.AddCloseFunc(func() error { return want })

	if err := lifecycle.Shutdown(context.Background()); !errors.Is(err, want) {
		t.Fatalf("expected closer error, got %v", err)
	}
}

func TestShutdownHonorsTimeout(t *testing.T) {
	t.Parallel()
	lifecycle := New()
	lifecycle.SetTimeout(10 * time.Millisecond)
	release := make(chan struct{})
	lifecycle.AddCloseFunc(func() error {
		<-release
		return nil
	})
	defer close(release)

	if err := lifecycle.Shutdown(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected shutdown timeout, got %v", err)
	}
}
