package credits

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestExecutionConcurrentEmployeesAndExecutionsStayIsolated(t *testing.T) {
	var calls atomic.Int64
	acquire := func(_ context.Context, s Subject) (Connection, error) {
		calls.Add(1)
		return Connection{BaseURL: "https://models.example.com/v1", APIKey: fmt.Sprintf("employee-%s-%s", s.OrganizationID, s.UserID)}, nil
	}
	a, err := NewExecution(Subject{OrganizationID: "org-2", UserID: "user-3"}, acquire)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewExecution(Subject{OrganizationID: "org-2", UserID: "user-4"}, acquire)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e, want := a, "employee-org-2-user-3"
			if i%2 == 1 {
				e, want = b, "employee-org-2-user-4"
			}
			connection, err := ConnectionFromContext(WithExecution(context.Background(), e))
			if err != nil || connection.APIKey != want {
				t.Error("employee key mismatch")
			}
		}(i)
	}
	wg.Wait()
	if calls.Load() != 2 {
		t.Fatalf("calls=%d want 2", calls.Load())
	}
	fresh, err := NewExecution(a.Subject(), acquire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fresh.AcquireDefault(context.Background()); err != nil || calls.Load() != 3 {
		t.Fatal("execution reused credential from earlier execution")
	}
}

func TestExecutionFailureNeverReturnsCredentialOrRetries(t *testing.T) {
	for _, cause := range []error{ErrDenied, errors.New("DO_NOT_LOG_CREDENTIAL"), context.Canceled} {
		calls := 0
		e, err := NewExecution(Subject{OrganizationID: "org-2", UserID: "user-3"}, func(context.Context, Subject) (Connection, error) {
			calls++
			return Connection{APIKey: "DO_NOT_LOG_CREDENTIAL"}, cause
		})
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			connection, err := e.AcquireDefault(context.Background())
			if err == nil || connection.APIKey != "" || err.Error() == "DO_NOT_LOG_CREDENTIAL" {
				t.Fatal("unsafe failure result")
			}
		}
		if calls != 1 {
			t.Fatal("implicit retry within execution")
		}
	}
}

func TestExecutionWaitingCallerCanCancel(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	e, err := NewExecution(Subject{OrganizationID: "org-2", UserID: "user-3"}, func(context.Context, Subject) (Connection, error) {
		close(started)
		<-release
		return Connection{BaseURL: "https://models.example.com/v1", APIKey: "employee-default"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer close(release)
	firstDone := make(chan struct{})
	go func() { defer close(firstDone); _, _ = e.AcquireDefault(context.Background()) }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.AcquireDefault(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled caller waited for credential")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := e.AcquireDefault(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("waiting caller ignored deadline")
	}
}

func TestExecutionMissingIdentityContextAndPanicFailClosed(t *testing.T) {
	if _, err := NewExecution(Subject{}, func(context.Context, Subject) (Connection, error) {
		t.Fatal("missing identity called provider")
		return Connection{}, nil
	}); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if _, err := ConnectionFromContext(context.Background()); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	e, err := NewExecution(Subject{OrganizationID: "org-2", UserID: "user-3"}, func(context.Context, Subject) (Connection, error) { panic("synthetic callback panic") })
	if err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("callback panic unexpectedly swallowed")
			}
		}()
		_, _ = e.AcquireDefault(context.Background())
	}()
	if _, err := e.AcquireDefault(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("panic left execution pending")
	}
}
