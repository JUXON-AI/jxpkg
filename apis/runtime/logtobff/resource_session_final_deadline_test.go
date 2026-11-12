package logtobff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// finalDeadlineFixture owns one real resource session and an atomic store clock.
type finalDeadlineFixture struct {
	runtime *Runtime
	cookie  *http.Cookie
	base    time.Time
	clock   atomic.Int64
	old     *session
}

// finalDeadlineCommitHook advances the fixture clock only after the route's
// third successful fenced commit: preparation, issuance, then final adoption.
type finalDeadlineCommitHook struct {
	clock   *atomic.Int64
	after   time.Time
	commits atomic.Int64
}

// renewalDuringVerificationKeys preserves real signature verification and runs
// one real renewal after issuance has committed and before verification returns.
type renewalDuringVerificationKeys struct {
	base    signatureVerifier
	renew   func()
	entered atomic.Bool
}

// TestResourceSessionRejectsIdleExpiryAfterFinalCommit rejects an unpublished
// session view when the idle deadline passes after its final Redis commit.
func TestResourceSessionRejectsIdleExpiryAfterFinalCommit(t *testing.T) {
	assertFinalDeadlineRejection(t, "session")
}

// TestResourceRequireRejectsIdleExpiryAfterFinalCommit keeps the protected
// handler unreachable when the idle deadline passes after its final commit.
func TestResourceRequireRejectsIdleExpiryAfterFinalCommit(t *testing.T) {
	assertFinalDeadlineRejection(t, "protected")
}

// TestResourceRequireKeepsRenewalDuringSignatureVerification covers a renewal
// after minting, so copying deadlines only during issuance cannot satisfy it.
func TestResourceRequireKeepsRenewalDuringSignatureVerification(t *testing.T) {
	var (
		fixture = newFinalDeadlineFixture(t)
		renewed *session
		gate    = &renewalDuringVerificationKeys{base: fixture.runtime.keys}
	)
	gate.renew = func() {
		fixture.clock.Store(fixture.base.Add(time.Second).UnixNano())
		response := renewalRequest(fixture.runtime, fixture.cookie, fixture.old.CSRF, nil)
		if response.Code != http.StatusOK || len(response.Result().Cookies()) != 0 {
			t.Fatalf("post-issuance renewal HTTP %d, cookie changes %d; want 200/0", response.Code, len(response.Result().Cookies()))
		}
		renewed = renewalReadSession(t, fixture.runtime, fixture.cookie)
		if !renewed.IdleUntil.After(fixture.old.IdleUntil) {
			t.Fatal("post-issuance renewal did not extend the committed idle deadline")
		}
		fixture.clock.Store(fixture.old.IdleUntil.Add(time.Second).UnixNano())
	}
	fixture.runtime.keys = gate
	observation := fixture.request("protected")
	if !gate.entered.Load() || renewed == nil {
		t.Fatal("protected request did not pass the post-issuance verification gate")
	}
	if observation.response.Code != http.StatusNoContent || observation.businessCalls != 1 || !observation.principalOK || len(observation.response.Result().Cookies()) != 0 {
		t.Fatalf("post-issuance renewed read HTTP %d, business calls %d, principal=%t, cookie changes %d; want 204/1/true/0", observation.response.Code, observation.businessCalls, observation.principalOK, len(observation.response.Result().Cookies()))
	}
	if observation.principal.ExpiresAt <= fixture.old.IdleUntil.Unix() || observation.principal.ExpiresAt > renewed.IdleUntil.Unix() {
		t.Error("protected principal did not adopt the currently renewed idle limit")
	}
	current := renewalReadSession(t, fixture.runtime, fixture.cookie)
	if !current.IdleUntil.Equal(renewed.IdleUntil) || !current.AbsoluteUntil.Equal(fixture.old.AbsoluteUntil) || !current.AuthenticatedAt.Equal(fixture.old.AuthenticatedAt) || current.CSRF != fixture.old.CSRF || current.Organization != fixture.old.Organization || current.Revision != fixture.old.Revision {
		t.Error("post-issuance read lost the committed renewal or changed authenticated identity")
	}
}

// newFinalDeadlineFixture completes login and short-idle setup before any
// route-specific Redis hook is installed, so initialization cannot be counted.
func newFinalDeadlineFixture(t *testing.T) *finalDeadlineFixture {
	t.Helper()
	var (
		a, authority = fixtureRuntime(t)
		fixture      = &finalDeadlineFixture{runtime: a, base: time.Now().UTC()}
	)
	fixture.clock.Store(fixture.base.UnixNano())
	a.store.now = func() time.Time { return time.Unix(0, fixture.clock.Load()).UTC() }
	fixture.cookie = loginFixture(t, a, authority)
	value, owner, err := a.store.acquire(context.Background(), fixture.cookie.Value)
	if err != nil {
		t.Fatal("cannot acquire the synthetic final-deadline session")
	}
	value.IdleUntil = fixture.base.Add(10 * time.Second)
	value.Until = value.IdleUntil
	if err := a.store.commit(context.Background(), fixture.cookie.Value, owner, fixture.cookie.Value, value, false /* remove */); err != nil {
		a.store.release(context.Background(), fixture.cookie.Value, owner)
		t.Fatal("cannot persist the synthetic final-deadline session")
	}
	fixture.old = renewalClone(t, value)
	return fixture
}

// assertFinalDeadlineRejection exercises an actual route and checks both the
// browser response and protected-context boundary without printing private data.
func assertFinalDeadlineRejection(t *testing.T, route string) {
	t.Helper()
	var (
		fixture = newFinalDeadlineFixture(t)
		hook    = &finalDeadlineCommitHook{clock: &fixture.clock, after: fixture.old.IdleUntil.Add(time.Second)}
	)
	fixture.runtime.store.db.AddHook(hook)
	observation := fixture.request(route)
	if hook.commits.Load() != 3 || fixture.clock.Load() != hook.after.UnixNano() {
		t.Fatalf("final-deadline route completed %d fenced commits, want exactly three before clock advance", hook.commits.Load())
	}
	if observation.response.Code != http.StatusUnauthorized || len(observation.response.Result().Cookies()) != 0 || observation.businessCalls != 0 || observation.principalOK || observation.principal.ExpiresAt != 0 {
		t.Fatalf("expired final result HTTP %d, cookie changes %d, business calls %d, principal=%t; want 401/0/0/false", observation.response.Code, len(observation.response.Result().Cookies()), observation.businessCalls, observation.principalOK)
	}
	var (
		body map[string]json.RawMessage
		code string
	)
	if json.Unmarshal(observation.response.Body.Bytes(), &body) != nil || len(body) != 1 || json.Unmarshal(body["error"], &code) != nil || code == "" {
		t.Error("expired final result published more than one bounded error field")
	}
}

// request exercises the real session handler or the real Require middleware;
// only the protected business callback records the published principal.
func (f *finalDeadlineFixture) request(route string) renewalRaceResult {
	if route == "session" {
		return renewalRaceResult{response: callAuth(f.runtime, http.MethodGet, "/auth/session", "", f.cookie, "")}
	}
	var (
		observation renewalRaceResult
		router      = gin.New()
	)
	router.POST("/protected", f.runtime.Require("read:credits"), func(c *gin.Context) {
		observation.businessCalls++
		observation.principal, observation.principalOK = FromContext(c.Request.Context())
		c.Status(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodPost, f.runtime.config.Origin+"/protected", nil)
	request.AddCookie(f.cookie)
	request.Header.Set("Origin", f.runtime.config.Origin)
	request.Header.Set("X-CSRF-Token", f.old.CSRF)
	request.Header.Set("X-Organization-ID", f.old.Organization)
	request.Header.Set("X-Organization-Revision", f.old.Revision)
	observation.response = httptest.NewRecorder()
	router.ServeHTTP(observation.response, request)
	return observation
}

// DialHook preserves the fixture client's existing connection hooks.
func (*finalDeadlineCommitHook) DialHook(next redis.DialHook) redis.DialHook { return next }

// ProcessPipelineHook preserves the fixture client's existing pipeline hooks.
func (*finalDeadlineCommitHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// ProcessHook observes the commit script and successful result before changing
// time; it never inspects Redis keys, serialized sessions or command formatting.
func (h *finalDeadlineCommitHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, command redis.Cmder) error {
		if err := next(ctx, command); err != nil {
			return err
		}
		args := command.Args()
		if command.Name() != "eval" || len(args) < 2 {
			return nil
		}
		script, ok := args[1].(string)
		if !ok || !strings.Contains(script, "if ARGV[5]=='1' then") {
			return nil
		}
		result, ok := command.(*redis.Cmd)
		if !ok {
			return errors.New("synthetic final commit command type invalid")
		}
		code, err := result.Int()
		if err != nil {
			return err
		}
		if code == 1 && h.commits.Add(1) == 3 {
			h.clock.Store(h.after.UnixNano())
		}
		return nil
	}
}

// VerifySignature executes the nested renewal only after real verification
// succeeds; the atomic gate lets that renewal verify its own token normally.
func (g *renewalDuringVerificationKeys) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	payload, err := g.base.VerifySignature(ctx, raw)
	if err == nil && g.entered.CompareAndSwap(false, true) {
		g.renew()
	}
	return payload, err
}
