package logtobff

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionWaitReadsCommittedStateAfterSlowOwner(t *testing.T) {
	a, _ := fixtureRuntime(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	id, err := a.store.create(ctx, &session{Revision: "1", Until: time.Now().Add(time.Minute)}, "")
	if err != nil {
		t.Fatal(err)
	}
	value, owner, err := a.store.acquire(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	defer a.store.release(ctx, id, owner)
	done := make(chan error, 1)
	go func() {
		defer close(done)
		current, nextOwner, err := a.store.acquire(ctx, id)
		if err == nil {
			defer a.store.release(ctx, id, nextOwner)
			if current.Revision != "2" {
				err = errors.New("waiter read an obsolete session")
			}
		}
		done <- err
	}()
	defer func() {
		cancel()
		for range done {
		}
	}()
	// Exceeds the old two-second contention limit without approaching the request budget.
	time.Sleep(2200 * time.Millisecond)
	value.Revision = "2"
	if err := a.store.commit(ctx, id, owner, id, value, false); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSessionWaitCancellationKeepsCurrentOwner(t *testing.T) {
	a, _ := fixtureRuntime(t)
	ctx := context.Background()
	id, err := a.store.create(ctx, &session{Until: time.Now().Add(time.Minute)}, "")
	if err != nil {
		t.Fatal(err)
	}
	_, owner, err := a.store.acquire(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	defer a.store.release(ctx, id, owner)
	wait, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
	defer cancel()
	if _, _, err := a.store.acquire(wait, id); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait cancellation lost: %v", err)
	}
	storedOwner, err := a.store.db.Get(ctx, a.store.prefix+"lock:"+id).Result()
	if err != nil || storedOwner != owner {
		t.Fatal("cancelled waiter changed the existing lease")
	}
}

func TestSessionQueueSharesAuthenticationBudgetAndPreservesBusinessContext(t *testing.T) {
	a, _ := fixtureRuntime(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	id, err := a.store.create(ctx, &session{Until: time.Now().Add(time.Minute)}, "")
	if err != nil {
		t.Fatal(err)
	}
	_, owner, err := a.store.acquire(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	defer a.store.release(ctx, id, owner)
	request := httptest.NewRequest("GET", "http://localhost:5180/protected", nil)
	requestContext, cancelRequest := context.WithCancel(context.Background())
	request = request.WithContext(requestContext)
	request.AddCookie(&http.Cookie{Name: a.config.CookieName, Value: id})
	response := httptest.NewRecorder()
	started := time.Now()
	var deadline time.Time
	var businessHasDeadline bool
	handler := a.withSession(func(r *http.Request, _ *session) result {
		deadline, _ = r.Context().Deadline()
		return result{status: 200, principal: &Principal{UserID: "synthetic"}}
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, businessHasDeadline = r.Context().Deadline()
		w.WriteHeader(http.StatusNoContent)
	}))
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.ServeHTTP(response, request)
	}()
	defer func() {
		cancelRequest()
		<-done
	}()
	time.Sleep(300 * time.Millisecond)
	a.store.release(ctx, id, owner)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("queued request did not finish")
	}
	if response.Code != http.StatusNoContent || deadline.IsZero() || deadline.After(started.Add(_authenticationTimeout+100*time.Millisecond)) || businessHasDeadline {
		t.Fatal("queue bypassed the shared budget or leaked its deadline into business processing")
	}
}
