package logtobff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/logto-io/go/v2/client"
)

// renewalRaceGate blocks only the first organization read, allowing a real
// renewal to finish while the earlier request retains its old snapshot.
type renewalRaceGate struct {
	base    http.RoundTripper
	blocked atomic.Bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

// RoundTrip preserves actual synthetic authority requests after the one-shot gate.
func (g *renewalRaceGate) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/api/my-account/organization-identity" && g.blocked.CompareAndSwap(false, true) {
		select {
		case g.entered <- struct{}{}:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		select {
		case <-g.release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	return g.base.RoundTrip(r)
}

// unblock joins normal completion and failed assertions without double close.
func (g *renewalRaceGate) unblock() { g.once.Do(func() { close(g.release) }) }

type renewalRaceResult struct {
	response      *httptest.ResponseRecorder
	principal     Principal
	principalOK   bool
	businessCalls int
}

type resourceRenewalRace struct {
	runtime *Runtime
	cookie  *http.Cookie
	base    time.Time
	clock   atomic.Int64
	old     *session
	gate    *renewalRaceGate
	done    chan renewalRaceResult
}

// TestResourceRequireKeepsConcurrentRenewal requires a pending protected request
// to use the current renewed deadline without deleting a valid browser session.
func TestResourceRequireKeepsConcurrentRenewal(t *testing.T) {
	var (
		race                 = startResourceRenewalRace(t, "protected")
		renewed              = race.renew(t)
		observation, current = race.complete(t, renewed)
	)
	if observation.response.Code != http.StatusNoContent || observation.businessCalls != 1 || !observation.principalOK {
		t.Errorf("renewed protected read HTTP %d, business calls %d, principal=%t; want 204/1/true", observation.response.Code, observation.businessCalls, observation.principalOK)
	}
	if current == nil || !observation.principalOK {
		return
	}
	var tokens map[string]client.AccessToken
	if err := json.Unmarshal([]byte(current.SDK[client.StorageKeyAccessTokenMap]), &tokens); err != nil {
		t.Fatal("renewed resource cache cannot be decoded")
	}
	var resourceExpiry int64
	for key, token := range tokens {
		if key == "@" {
			continue
		}
		var claims jwt.RegisteredClaims
		if _, _, err := jwt.NewParser().ParseUnverified(token.Token, &claims); err != nil || claims.ExpiresAt == nil {
			t.Fatal("synthetic verified resource token has no valid expiry")
		}
		if resourceExpiry != 0 {
			t.Fatal("resource fixture retained more than one scoped credential")
		}
		resourceExpiry = claims.ExpiresAt.Unix()
	}
	if resourceExpiry == 0 || observation.principal.ExpiresAt != min(resourceExpiry, renewed.IdleUntil.Unix()) || observation.principal.ExpiresAt <= race.old.IdleUntil.Unix() {
		t.Error("protected principal did not retain the current token/session deadline minimum")
	}
}

// TestResourceSessionKeepsConcurrentRenewal requires a pending session view to
// remain successful after a pure renewal rather than report an identity conflict.
func TestResourceSessionKeepsConcurrentRenewal(t *testing.T) {
	var (
		race                 = startResourceRenewalRace(t, "session")
		renewed              = race.renew(t)
		observation, current = race.complete(t, renewed)
	)
	if observation.response.Code != http.StatusOK {
		t.Errorf("renewed session view HTTP %d, want 200 without an identity conflict", observation.response.Code)
		return
	}
	if current == nil {
		return
	}
	var (
		body          = sessionBody(t, observation.response)
		expiresAt, ok = body["expires_at"].(float64)
	)
	if !ok || int64(expiresAt) != renewed.IdleUntil.Unix() {
		t.Error("session view did not report the committed renewed deadline")
	}
}

// startResourceRenewalRace establishes a real resource session and starts one
// old read; all clock changes use an atomic value shared with store.now.
func startResourceRenewalRace(t *testing.T, route string) *resourceRenewalRace {
	t.Helper()
	var (
		a, authority = fixtureRuntime(t)
		race         = &resourceRenewalRace{runtime: a, base: time.Now().UTC(), done: make(chan renewalRaceResult, 1)}
	)
	race.clock.Store(race.base.UnixNano())
	a.store.now = func() time.Time { return time.Unix(0, race.clock.Load()).UTC() }
	race.cookie = loginFixture(t, a, authority)
	value, owner, err := a.store.acquire(context.Background(), race.cookie.Value)
	if err != nil {
		t.Fatal("cannot acquire the synthetic pre-renewal session")
	}
	value.IdleUntil = race.base.Add(10 * time.Second)
	value.Until = value.IdleUntil
	if err := a.store.commit(context.Background(), race.cookie.Value, owner, race.cookie.Value, value, false /* remove */); err != nil {
		a.store.release(context.Background(), race.cookie.Value, owner)
		t.Fatal("cannot persist the synthetic short idle deadline")
	}
	race.old = renewalClone(t, value)
	race.gate = &renewalRaceGate{base: a.http.Transport, entered: make(chan struct{}, 1), release: make(chan struct{})}
	a.http.Transport = race.gate
	t.Cleanup(func() {
		race.gate.unblock()
		for range race.done {
		}
	})
	go func() {
		defer close(race.done)
		if route == "session" {
			race.done <- renewalRaceResult{response: callAuth(a, http.MethodGet, "/auth/session", "", race.cookie, "")}
			return
		}
		var (
			observation renewalRaceResult
			router      = gin.New()
		)
		router.POST("/protected", a.Require("read:credits"), func(c *gin.Context) {
			observation.businessCalls++
			observation.principal, observation.principalOK = FromContext(c.Request.Context())
			c.Status(http.StatusNoContent)
		})
		request := httptest.NewRequest(http.MethodPost, a.config.Origin+"/protected", nil)
		request.AddCookie(race.cookie)
		request.Header.Set("Origin", a.config.Origin)
		request.Header.Set("X-CSRF-Token", race.old.CSRF)
		request.Header.Set("X-Organization-ID", race.old.Organization)
		request.Header.Set("X-Organization-Revision", race.old.Revision)
		observation.response = httptest.NewRecorder()
		router.ServeHTTP(observation.response, request)
		race.done <- observation
	}()
	waitForAuthority(t, race.gate.entered)
	return race
}

// renew performs the actual signed POST while the first organization GET is
// gated and proves only idle, rather than identity or absolute policy, changed.
func (r *resourceRenewalRace) renew(t *testing.T) *session {
	t.Helper()
	r.clock.Store(r.base.Add(time.Second).UnixNano())
	response := renewalRequest(r.runtime, r.cookie, r.old.CSRF, nil)
	if response.Code != http.StatusOK || len(response.Result().Cookies()) != 0 {
		t.Fatalf("real concurrent renewal HTTP %d, cookie changes %d; want 200/0", response.Code, len(response.Result().Cookies()))
	}
	renewed := renewalReadSession(t, r.runtime, r.cookie)
	if !renewed.IdleUntil.After(r.base.Add(11*time.Second)) || !renewed.Until.Equal(renewed.IdleUntil) || !renewed.AbsoluteUntil.Equal(r.old.AbsoluteUntil) || !renewed.AuthenticatedAt.Equal(r.old.AuthenticatedAt) || renewed.PolicyVersion != r.old.PolicyVersion || renewed.CSRF != r.old.CSRF || renewed.Organization != r.old.Organization || renewed.Revision != r.old.Revision {
		t.Fatal("concurrent renewal did not preserve the authenticated identity and policy")
	}
	return renewed
}

// complete expires only the old snapshot and checks the persisted renewal and
// browser cookie before returning observations to the route-specific test.
func (r *resourceRenewalRace) complete(t *testing.T, renewed *session) (renewalRaceResult, *session) {
	t.Helper()
	r.clock.Store(r.base.Add(11 * time.Second).UnixNano())
	r.gate.unblock()
	var (
		observation = <-r.done
		cleared     bool
	)
	for _, cookie := range observation.response.Result().Cookies() {
		if cookie.Name == r.cookie.Name && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	current, owner, err := r.runtime.store.acquire(context.Background(), r.cookie.Value)
	if err == nil {
		r.runtime.store.release(context.Background(), r.cookie.Value, owner)
	}
	t.Logf("renewal_race http=%d renewed_session_present=%t cookie_cleared=%t", observation.response.Code, err == nil, cleared)
	if cleared {
		t.Error("pending old snapshot cleared a concurrently renewed browser cookie")
	}
	if err != nil {
		if errors.Is(err, _errMissing) {
			t.Error("pending old snapshot deleted the committed renewed session")
		} else {
			t.Error("committed renewal is not readable after the pending request")
		}
		return observation, nil
	}
	if !current.IdleUntil.Equal(renewed.IdleUntil) || !current.Until.Equal(renewed.Until) || !current.AbsoluteUntil.Equal(renewed.AbsoluteUntil) || !current.AuthenticatedAt.Equal(renewed.AuthenticatedAt) || current.PolicyVersion != renewed.PolicyVersion || current.CSRF != renewed.CSRF || current.Organization != renewed.Organization || current.Revision != renewed.Revision {
		t.Error("pending old snapshot overwrote the committed renewal or identity")
	}
	return observation, current
}
