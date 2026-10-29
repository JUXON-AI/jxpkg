package logtobff

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

type redisProcessAudit struct {
	mu      sync.Mutex
	names   []string
	latency time.Duration
}

type lateAcquireWriteHook struct {
	mu     sync.Mutex
	armed  bool
	cancel context.CancelFunc
}

func (h *lateAcquireWriteHook) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (h *lateAcquireWriteHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (h *lateAcquireWriteHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		h.mu.Lock()
		armed := h.armed
		if armed {
			h.armed = false
		}
		cancel := h.cancel
		h.mu.Unlock()
		if !armed || cmd.Name() != "eval" {
			return next(ctx, cmd)
		}
		// Execute the script without the caller's cancellation, then report the
		// canceled response. This models Redis committing a late Eval write.
		if err := next(context.WithoutCancel(ctx), cmd); err != nil {
			return err
		}
		cancel()
		return context.Canceled
	}
}

func (h *lateAcquireWriteHook) arm(cancel context.CancelFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cancel = cancel
	h.armed = true
}

func (h *redisProcessAudit) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (h *redisProcessAudit) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (h *redisProcessAudit) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		h.mu.Lock()
		h.names = append(h.names, cmd.Name())
		latency := h.latency
		h.mu.Unlock()
		if latency > 0 {
			timer := time.NewTimer(latency)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
			}
		}
		return next(ctx, cmd)
	}
}

func (h *redisProcessAudit) commands() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.names...)
}

func assertRedisCommands(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("Redis commands = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Redis commands = %v, want %v", got, want)
		}
	}
}

func TestSessionAcquireUsesOneAtomicRedisCommand(t *testing.T) {
	a, _ := fixtureRuntime(t)
	ctx := context.Background()
	id, err := a.store.create(ctx, renewalPolicySession(time.Now()), "")
	if err != nil {
		t.Fatal(err)
	}
	audit := &redisProcessAudit{}
	a.store.db.AddHook(audit)
	value, owner, err := a.store.acquire(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	assertRedisCommands(t, audit.commands(), []string{"eval"})
	if err := a.store.commit(ctx, id, owner, id, value, false); err != nil {
		t.Fatal(err)
	}
}

func TestSessionAcquireRetryDelayIsBoundedAndBudgetCapped(t *testing.T) {
	for range 1000 {
		delay := sessionAcquireRetryDelay(time.Second)
		if delay < sessionAcquireRetryMin || delay > sessionAcquireRetryMax {
			t.Fatalf("retry delay = %s, want [%s,%s]", delay, sessionAcquireRetryMin, sessionAcquireRetryMax)
		}
	}
	if delay := sessionAcquireRetryDelay(time.Millisecond); delay != time.Millisecond {
		t.Fatalf("remaining budget delay = %s, want 1ms", delay)
	}
}

func TestSessionAcquireMissingSourceIsImmediateAndLeavesNoLease(t *testing.T) {
	a, _ := fixtureRuntime(t)
	ctx := context.Background()
	id := testOpaque(t)
	if _, _, err := a.store.acquire(ctx, id); !errors.Is(err, _errMissing) {
		t.Fatalf("missing session error = %v", err)
	}
	lockKey := a.store.prefix + "lock:" + id
	if remaining, err := a.store.db.Exists(ctx, lockKey).Result(); err != nil || remaining != 0 {
		t.Fatalf("missing session left lease: remaining=%d err=%v", remaining, err)
	}

	// An orphaned lock must not turn an already-missing source into busy or
	// cause acquire to replace the foreign owner.
	if err := a.store.db.Set(ctx, lockKey, "stale-owner", time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, _, err := a.store.acquire(wait, id); !errors.Is(err, _errMissing) {
		t.Fatalf("missing source behind stale lease error = %v", err)
	}
	if owner, err := a.store.db.Get(ctx, lockKey).Result(); err != nil || owner != "stale-owner" {
		t.Fatalf("foreign stale lease changed: owner=%q err=%v", owner, err)
	}
}

func TestSessionAcquireLuaErrorReleasesLateLease(t *testing.T) {
	a, _ := fixtureRuntime(t)
	ctx := context.Background()
	id := testOpaque(t)
	sourceKey := a.store.prefix + "s:" + id
	lockKey := a.store.prefix + "lock:" + id
	t.Cleanup(func() { _ = a.store.db.Del(context.Background(), sourceKey, lockKey).Err() })
	if err := a.store.db.RPush(ctx, sourceKey, "wrong-type").Err(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.store.acquire(ctx, id); err == nil || errors.Is(err, _errMissing) || errors.Is(err, _errBusy) {
		t.Fatalf("wrong-type source error = %v", err)
	}
	if remaining, err := a.store.db.Exists(ctx, lockKey).Result(); err != nil || remaining != 0 {
		t.Fatalf("Lua error left lease: remaining=%d err=%v", remaining, err)
	}
}

func TestSessionAcquireCanceledLateWriteReleasesOwnedLease(t *testing.T) {
	a, _ := fixtureRuntime(t)
	id, err := a.store.create(context.Background(), renewalPolicySession(time.Now()), "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	hook := &lateAcquireWriteHook{}
	a.store.db.AddHook(hook)
	hook.arm(cancel)
	if _, _, err := a.store.acquire(ctx, id); !errors.Is(err, context.Canceled) {
		t.Fatalf("late canceled Eval error = %v", err)
	}
	lockKey := a.store.prefix + "lock:" + id
	if remaining, err := a.store.db.Exists(context.Background(), lockKey).Result(); err != nil || remaining != 0 {
		t.Fatalf("canceled late Eval left lease: remaining=%d err=%v", remaining, err)
	}
}

func TestIdentityOnlyNoContentionUsesFourRedisRoundTrips(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	const commandLatency = 10 * time.Millisecond
	audit := &redisProcessAudit{latency: commandLatency}
	a.store.db.AddHook(audit)
	started := time.Now()
	response := callAuth(a, http.MethodGet, "/auth/session", "", cookie, "")
	elapsed := time.Since(started)
	commands := audit.commands()
	t.Logf("session_reuse redis_commands=%d injected_latency=%s elapsed=%s names=%v", len(commands), commandLatency, elapsed, commands)
	if response.Code != http.StatusOK {
		t.Fatalf("session reuse HTTP %d", response.Code)
	}
	assertRedisCommands(t, commands, []string{"eval", "eval", "eval", "eval"})
}

func TestSessionLeaseOwnerFencesCommitAndRelease(t *testing.T) {
	a, _ := fixtureRuntime(t)
	ctx := context.Background()
	id, err := a.store.create(ctx, renewalPolicySession(time.Now()), "")
	if err != nil {
		t.Fatal(err)
	}
	value, owner, err := a.store.acquire(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	lockKey := a.store.prefix + "lock:" + id
	value.Revision = "2"
	if err := a.store.commit(ctx, id, "wrong-owner", id, value, false); !errors.Is(err, _errMissing) {
		t.Fatalf("wrong owner commit error = %v", err)
	}
	if lease, err := a.store.db.Get(ctx, lockKey).Result(); err != nil || lease != owner {
		t.Fatalf("wrong owner commit changed lease: owner=%q err=%v", lease, err)
	}
	a.store.release(ctx, id, "wrong-owner")
	if lease, err := a.store.db.Get(ctx, lockKey).Result(); err != nil || lease != owner {
		t.Fatalf("wrong owner release changed lease: owner=%q err=%v", lease, err)
	}
	if err := a.store.commit(ctx, id, owner, id, value, false); err != nil {
		t.Fatal(err)
	}
}

func TestSessionWaitReadsCommittedStateAfterSlowOwner(t *testing.T) {
	a, _ := fixtureRuntime(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	id, err := a.store.create(ctx, renewalPolicySession(time.Now()), "")
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
	id, err := a.store.create(ctx, renewalPolicySession(time.Now()), "")
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
	id, err := a.store.create(ctx, renewalPolicySession(time.Now()), "")
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
