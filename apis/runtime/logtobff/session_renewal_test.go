package logtobff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/logto-io/go/v2/client"
	"github.com/redis/go-redis/v9"
)

func renewalClone(t *testing.T, value *session) *session {
	t.Helper()
	out := *value
	out.SDK = map[string]string{}
	for key, item := range value.SDK {
		out.SDK[key] = item
	}
	return &out
}

func renewalReadSession(t *testing.T, a *Runtime, cookie *http.Cookie) *session {
	t.Helper()
	value, owner, err := a.store.acquire(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	defer a.store.release(context.Background(), cookie.Value, owner)
	return renewalClone(t, value)
}

func renewalRequest(a *Runtime, cookie *http.Cookie, csrf string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	request := httptest.NewRequest("POST", "http://localhost:5180/auth/session", strings.NewReader(`{}`))
	request.RequestURI = request.URL.RequestURI()
	if cookie != nil {
		request.AddCookie(cookie)
	}
	request.Header.Set("Origin", a.config.Origin)
	request.Header.Set("X-CSRF-Token", csrf)
	request.Header.Set("X-Organization-ID", "org-one")
	request.Header.Set("X-Organization-Revision", "1")
	request.Header.Set("Content-Type", "application/json")
	if mutate != nil {
		mutate(request)
	}
	response := httptest.NewRecorder()
	a.Handler().ServeHTTP(response, request)
	return response
}

func renewalBody(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if response.Code < 200 || response.Code >= 300 {
		t.Fatalf("renewal HTTP %d: %s", response.Code, response.Body.String())
	}
	return sessionBody(t, response)
}

func renewalExpiresAt(t *testing.T, body map[string]any) time.Time {
	t.Helper()
	seconds, ok := body["expires_at"].(float64)
	if !ok {
		t.Fatalf("expires_at missing: %#v", body["expires_at"])
	}
	return time.Unix(int64(seconds), 0)
}

func renewalPolicySession(now time.Time) *session {
	return &session{
		SDK:             map[string]string{client.StorageKeyRefreshToken: "refresh-current"},
		Subject:         "user-one",
		Organization:    "org-one",
		Revision:        "1",
		CSRF:            "csrf-current",
		Until:           now.Add(sessionIdleLifetime),
		PolicyVersion:   sessionPolicyVersion,
		AuthenticatedAt: now,
		IdleUntil:       now.Add(sessionIdleLifetime),
		AbsoluteUntil:   now.Add(sessionAbsoluteLifetime),
	}
}

func putEncryptedSessionFixture(t *testing.T, a *Runtime, id string, value any, ttl time.Duration) {
	t.Helper()
	key := a.store.prefix + "s:" + id
	data, err := a.store.seal(key, value)
	if err != nil {
		t.Fatal("seal session fixture")
	}
	if err := a.store.db.Set(context.Background(), key, data, ttl).Err(); err != nil {
		t.Fatal("write session fixture")
	}
	t.Cleanup(func() {
		_ = a.store.db.Del(context.Background(), key).Err()
	})
}

func legacySessionPayload(t *testing.T, value *session, now time.Time, policyVersion *uint64) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal("marshal session payload seed")
	}
	var payload map[string]any
	if json.Unmarshal(data, &payload) != nil {
		t.Fatal("decode session payload seed")
	}
	payload["until"] = now.Add(30 * time.Minute)
	delete(payload, "authenticated_at")
	delete(payload, "idle_until")
	delete(payload, "absolute_until")
	delete(payload, "policy_version")
	if policyVersion != nil {
		payload["policy_version"] = *policyVersion
	}
	return payload
}

func requireNoRuntimeCookie(t *testing.T, response http.Response, name string) {
	t.Helper()
	for _, cookie := range response.Cookies() {
		if cookie.Name == name {
			t.Fatalf("unexpected session cookie: %#v", cookie)
		}
	}
}

type responseDeliveryBarrier struct {
	header   http.Header
	entered  chan struct{}
	release  chan struct{}
	blocked  sync.Once
	status   int
	bodySize int
}

func newResponseDeliveryBarrier() *responseDeliveryBarrier {
	return &responseDeliveryBarrier{header: make(http.Header), entered: make(chan struct{}), release: make(chan struct{})}
}

func (w *responseDeliveryBarrier) Header() http.Header { return w.header }

func (w *responseDeliveryBarrier) WriteHeader(status int) {
	w.blocked.Do(func() {
		close(w.entered)
		<-w.release
	})
	if w.status == 0 {
		w.status = status
	}
}

func (w *responseDeliveryBarrier) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	w.bodySize += len(data)
	return len(data), nil
}

func TestLegacySessionPolicyFailsClosedBeforeAuthorityOrBusiness(t *testing.T) {
	for _, policy := range []struct {
		name  string
		value *uint64
	}{
		{name: "missing version"},
		{name: "explicit zero", value: func() *uint64 { value := uint64(0); return &value }()},
	} {
		for _, route := range []string{"session", "protected"} {
			t.Run(policy.name+"/"+route, func(t *testing.T) {
				a, f := fixtureRuntime(t, "")
				cookie := loginFixture(t, a, f)
				current := renewalReadSession(t, a, cookie)
				now := a.store.nowTime()
				putEncryptedSessionFixture(t, a, cookie.Value, legacySessionPayload(t, current, now, policy.value), 30*time.Minute)

				observer := observeIdentity(t, a, false)
				refreshes := f.refreshes
				profileRequests := f.profileRequests.Load()
				userInfoCalls := f.userInfoCalls.Load()
				businessCalls := 0
				var response *httptest.ResponseRecorder
				if route == "session" {
					response = callAuth(a, "GET", "/auth/session", "", cookie, "")
				} else {
					router := gin.New()
					router.POST("/protected", a.Require(), func(c *gin.Context) {
						businessCalls++
						c.Status(http.StatusNoContent)
					})
					request := httptest.NewRequest(http.MethodPost, "http://localhost:5180/protected", nil)
					request.AddCookie(cookie)
					request.Header.Set("Origin", a.config.Origin)
					request.Header.Set("X-CSRF-Token", current.CSRF)
					request.Header.Set("X-Organization-ID", current.Organization)
					request.Header.Set("X-Organization-Revision", current.Revision)
					response = httptest.NewRecorder()
					router.ServeHTTP(response, request)
				}

				if response.Code != http.StatusUnauthorized {
					t.Fatalf("legacy policy status = %d body=%s", response.Code, response.Body.String())
				}
				requireNoRuntimeCookie(t, *response.Result(), a.config.CookieName)
				if businessCalls != 0 || len(observer.paths) != 0 || f.refreshes != refreshes || f.profileRequests.Load() != profileRequests || f.userInfoCalls.Load() != userInfoCalls {
					t.Fatalf("legacy policy crossed authority/business boundary: business=%d paths=%v refreshes=%d->%d profile=%d->%d userinfo=%d->%d", businessCalls, observer.paths, refreshes, f.refreshes, profileRequests, f.profileRequests.Load(), userInfoCalls, f.userInfoCalls.Load())
				}
				if remaining := a.store.db.Exists(context.Background(), a.store.prefix+"s:"+cookie.Value).Val(); remaining != 1 {
					t.Fatalf("invalid session store state = %d, want retained until TTL", remaining)
				}
				// A copied/replayed request cannot cross the authority boundary while the old record remains valid for cleanup by TTL.
				replay := callAuth(a, "GET", "/auth/session", "", cookie, "")
				if replay.Code != http.StatusUnauthorized || len(observer.paths) != 0 {
					t.Fatalf("legacy replay crossed authority: HTTP %d paths=%v", replay.Code, observer.paths)
				}
				requireNoRuntimeCookie(t, *replay.Result(), a.config.CookieName)
			})
		}
	}
}

func TestLateInvalidResponseCannotClearNewV2SessionCookie(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	oldCookie := loginFixture(t, a, f)
	current := renewalReadSession(t, a, oldCookie)
	putEncryptedSessionFixture(t, a, oldCookie.Value, legacySessionPayload(t, current, a.store.nowTime(), nil), 30*time.Minute)

	observer := observeIdentity(t, a, false)
	refreshes := f.refreshes
	profileRequests := f.profileRequests.Load()
	userInfoCalls := f.userInfoCalls.Load()
	businessCalls := 0
	router := gin.New()
	router.POST("/protected", a.Require(), func(c *gin.Context) {
		businessCalls++
		c.Status(http.StatusNoContent)
	})
	origin, err := url.Parse(a.config.Origin)
	if err != nil {
		t.Fatal("parse fixture origin")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal("create cookie jar")
	}
	jar.SetCookies(origin, []*http.Cookie{oldCookie})

	oldRequest := httptest.NewRequest(http.MethodPost, a.config.Origin+"/protected", nil)
	oldRequest.AddCookie(oldCookie)
	oldRequest.Header.Set("Origin", a.config.Origin)
	oldRequest.Header.Set("X-CSRF-Token", current.CSRF)
	oldRequest.Header.Set("X-Organization-ID", current.Organization)
	oldRequest.Header.Set("X-Organization-Revision", current.Revision)
	oldResponse := newResponseDeliveryBarrier()
	oldDone := make(chan struct{})
	go func() {
		defer close(oldDone)
		router.ServeHTTP(oldResponse, oldRequest)
	}()
	select {
	case <-oldResponse.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("old invalid response did not reach delivery barrier")
	}
	if businessCalls != 0 || len(observer.paths) != 0 || f.refreshes != refreshes || f.profileRequests.Load() != profileRequests || f.userInfoCalls.Load() != userInfoCalls {
		t.Fatalf("old invalid request crossed authority/business before response delivery: business=%d paths=%v refreshes=%d->%d profile=%d->%d userinfo=%d->%d", businessCalls, observer.paths, refreshes, f.refreshes, profileRequests, f.profileRequests.Load(), userInfoCalls, f.userInfoCalls.Load())
	}

	newCookie := loginFixture(t, a, f)
	jar.SetCookies(origin, []*http.Cookie{newCookie})
	close(oldResponse.release)
	select {
	case <-oldDone:
	case <-time.After(3 * time.Second):
		t.Fatal("old invalid response did not complete after new login")
	}
	if oldResponse.status != http.StatusUnauthorized || businessCalls != 0 {
		t.Fatalf("old invalid response status=%d business=%d", oldResponse.status, businessCalls)
	}
	oldHTTPResponse := &http.Response{Header: oldResponse.header}
	requireNoRuntimeCookie(t, *oldHTTPResponse, a.config.CookieName)
	// Deliver the old response last, as a browser would apply it after S1 was installed.
	jar.SetCookies(origin, oldHTTPResponse.Cookies())
	cookies := jar.Cookies(origin)
	var active *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == a.config.CookieName {
			active = cookie
			break
		}
	}
	if active == nil || active.Value != newCookie.Value {
		t.Fatalf("late invalid response removed new v2 cookie: %#v, want new cookie present", active)
	}

	session := callAuth(a, "GET", "/auth/session", "", active, "")
	if session.Code != http.StatusOK {
		t.Fatalf("new v2 session failed after late invalid delivery: HTTP %d body=%s", session.Code, session.Body.String())
	}
	csrf := sessionBody(t, session)["csrf_token"].(string)
	protected := httptest.NewRequest(http.MethodPost, a.config.Origin+"/protected", nil)
	protected.AddCookie(active)
	protected.Header.Set("Origin", a.config.Origin)
	protected.Header.Set("X-CSRF-Token", csrf)
	protected.Header.Set("X-Organization-ID", "org-one")
	protected.Header.Set("X-Organization-Revision", "1")
	protectedResponse := httptest.NewRecorder()
	router.ServeHTTP(protectedResponse, protected)
	if protectedResponse.Code != http.StatusNoContent || businessCalls != 1 {
		t.Fatalf("new v2 Require failed after late invalid delivery: HTTP %d business=%d", protectedResponse.Code, businessCalls)
	}
}

func TestSessionRenewalInitializationAndGetReadOnly(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		resource []string
	}{
		{name: "identity-only", resource: []string{""}},
		{name: "resource", resource: nil},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			a, f := fixtureRuntime(t, testCase.resource...)
			cookie := loginFixture(t, a, f)
			value := renewalReadSession(t, a, cookie)
			if value.PolicyVersion != sessionPolicyVersion || value.AuthenticatedAt.IsZero() {
				t.Fatalf("new session policy missing: %#v", value)
			}
			if value.IdleUntil.Sub(value.AuthenticatedAt) != sessionIdleLifetime || value.AbsoluteUntil.Sub(value.AuthenticatedAt) != sessionAbsoluteLifetime || !value.Until.Equal(value.IdleUntil) {
				t.Fatalf("unexpected initial deadlines: auth=%s idle=%s absolute=%s until=%s", value.AuthenticatedAt, value.IdleUntil, value.AbsoluteUntil, value.Until)
			}
			if cookie.MaxAge < int((sessionAbsoluteLifetime-2*time.Second)/time.Second) || cookie.MaxAge > int(sessionAbsoluteLifetime/time.Second) {
				t.Fatalf("cookie max age %d is not the absolute cap", cookie.MaxAge)
			}
			firstExpiry := renewalExpiresAt(t, renewalBody(t, callAuth(a, "GET", "/auth/session", "", cookie, "")))
			a.store.now = func() time.Time { return value.AuthenticatedAt.Add(time.Minute) }
			response := callAuth(a, "GET", "/auth/session", "", cookie, "")
			secondExpiry := renewalExpiresAt(t, renewalBody(t, response))
			if !firstExpiry.Equal(secondExpiry) || len(response.Result().Cookies()) != 0 {
				t.Fatalf("GET renewed session: before=%s after=%s cookies=%v", firstExpiry, secondExpiry, response.Result().Cookies())
			}
			after := renewalReadSession(t, a, cookie)
			if !after.IdleUntil.Equal(value.IdleUntil) || !after.AbsoluteUntil.Equal(value.AbsoluteUntil) {
				t.Fatal("GET changed Redis deadlines")
			}
		})
	}
}

func TestSessionRenewalPostExtendsIdleButNotAbsolute(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		resource []string
	}{
		{name: "identity-only", resource: []string{""}},
		{name: "resource", resource: nil},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			a, f := fixtureRuntime(t, testCase.resource...)
			cookie := loginFixture(t, a, f)
			current := sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
			csrf := current["csrf_token"].(string)
			before := renewalReadSession(t, a, cookie)
			a.store.now = func() time.Time { return before.AuthenticatedAt.Add(time.Minute) }
			refreshesBefore := f.refreshes
			response := renewalRequest(a, cookie, csrf, nil)
			body := renewalBody(t, response)
			after := renewalReadSession(t, a, cookie)
			wantIdle := before.AuthenticatedAt.Add(time.Minute + sessionIdleLifetime)
			if !after.IdleUntil.Equal(wantIdle) || !after.Until.Equal(wantIdle) || !after.AbsoluteUntil.Equal(before.AbsoluteUntil) || renewalExpiresAt(t, body).Unix() != wantIdle.Unix() {
				t.Fatalf("renewed deadlines: want idle=%s absolute=%s got idle=%s until=%s absolute=%s body=%s", wantIdle, before.AbsoluteUntil, after.IdleUntil, after.Until, after.AbsoluteUntil, renewalExpiresAt(t, body))
			}
			if len(response.Result().Cookies()) != 0 {
				t.Fatal("same-ID renewal rewrote the browser cookie")
			}
			beforeRefresh, afterRefresh := before.SDK[client.StorageKeyRefreshToken], after.SDK[client.StorageKeyRefreshToken]
			if testCase.resource == nil && (beforeRefresh == "" || afterRefresh == "" || afterRefresh != beforeRefresh && f.refreshes <= refreshesBefore) {
				t.Fatalf("resource-mode refresh token retention failed: before_present=%t after_present=%t changed=%t refreshes=%d", beforeRefresh != "", afterRefresh != "", afterRefresh != beforeRefresh, f.refreshes-refreshesBefore)
			}
		})
	}
}

func TestSessionRenewalIdleIsCappedByAbsoluteDeadline(t *testing.T) {
	now := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	absolute := now.Add(sessionAbsoluteLifetime)
	if got := nextSessionIdle(now.Add(6*24*time.Hour+23*time.Hour), absolute); !got.Equal(absolute) {
		t.Fatalf("idle renewal exceeded absolute cap: %s", got)
	}
	if got := nextSessionIdle(now, absolute); !got.Equal(now.Add(sessionIdleLifetime)) {
		t.Fatalf("normal idle renewal = %s", got)
	}
	if got := sessionCookieMaxAge(renewalPolicySession(now), now); got != int(sessionAbsoluteLifetime/time.Second) {
		t.Fatalf("policy cookie max age = %d", got)
	}
	if got := sessionCookieMaxAge(&session{Until: now.Add(30 * time.Minute)}, now); got != -1 {
		t.Fatalf("legacy cookie was accepted: max age = %d", got)
	}
}

func TestLegacyUntilOnlySessionPolicyIsRejected(t *testing.T) {
	now := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	value := &session{Until: now.Add(30 * time.Minute)}
	if err := validateSessionSchema(value, now); !errors.Is(err, _errInvalid) {
		t.Fatalf("legacy policy accepted: %v", err)
	}
	if _, err := sessionDeadline(value, now); !errors.Is(err, _errInvalid) {
		t.Fatalf("legacy deadline accepted: %v", err)
	}
}

func TestMalformedSessionPolicyFailsClosed(t *testing.T) {
	now := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	valid := renewalPolicySession(now)
	tests := []struct {
		name   string
		change func(*session)
	}{
		{name: "zero version", change: func(value *session) {
			value.PolicyVersion = 0
			value.AuthenticatedAt = time.Time{}
			value.IdleUntil = time.Time{}
			value.AbsoluteUntil = time.Time{}
			value.Until = now.Add(30 * time.Minute)
		}},
		{name: "mixed zero version", change: func(value *session) { value.PolicyVersion = 0 }},
		{name: "unknown policy", change: func(value *session) { value.PolicyVersion = 3 }},
		{name: "missing authentication", change: func(value *session) { value.AuthenticatedAt = time.Time{} }},
		{name: "missing idle", change: func(value *session) { value.IdleUntil = time.Time{} }},
		{name: "missing absolute", change: func(value *session) { value.AbsoluteUntil = time.Time{} }},
		{name: "legacy projection mismatch", change: func(value *session) { value.Until = value.Until.Add(-time.Minute) }},
		{name: "absolute not seven days", change: func(value *session) {
			value.AbsoluteUntil = value.AuthenticatedAt.Add(sessionAbsoluteLifetime + time.Second)
		}},
		{name: "idle after absolute", change: func(value *session) {
			value.IdleUntil = value.AbsoluteUntil.Add(time.Second)
			value.Until = value.IdleUntil
		}},
		{name: "idle before authentication", change: func(value *session) {
			value.IdleUntil = value.AuthenticatedAt.Add(-time.Second)
			value.Until = value.IdleUntil
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			value := renewalClone(t, valid)
			testCase.change(value)
			if err := validateSessionSchema(value, now); !errors.Is(err, _errInvalid) {
				t.Fatalf("invalid policy accepted: %v", err)
			}
		})
	}
	if err := validateSessionSchema(valid, now); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	expired := renewalClone(t, valid)
	expired.IdleUntil = now.Add(time.Second)
	expired.Until = expired.IdleUntil
	if _, err := sessionDeadline(expired, now.Add(2*time.Second)); !errors.Is(err, _errMissing) {
		t.Fatalf("expired policy exposed: %v", err)
	}
}

func TestSessionRenewalRejectsUnboundOrAmbiguousRequests(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	body := sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
	csrf := body["csrf_token"].(string)
	t0 := renewalReadSession(t, a, cookie).AuthenticatedAt
	a.store.now = func() time.Time { return t0.Add(time.Minute) }
	before := renewalReadSession(t, a, cookie)
	tests := []struct {
		name   string
		mutate func(*http.Request)
		status int
	}{
		{name: "no cookie", mutate: func(r *http.Request) { r.Header.Del("Cookie") }, status: 401},
		{name: "duplicate cookie", mutate: func(r *http.Request) { r.Header.Add("Cookie", cookie.String()) }, status: 401},
		{name: "bearer", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer forbidden") }, status: 400},
		{name: "wrong host", mutate: func(r *http.Request) { r.Host = "foreign.invalid" }, status: 403},
		{name: "missing origin", mutate: func(r *http.Request) { r.Header.Set("Origin", "") }, status: 403},
		{name: "duplicate origin", mutate: func(r *http.Request) { r.Header.Add("Origin", a.config.Origin) }, status: 403},
		{name: "missing csrf", mutate: func(r *http.Request) { r.Header.Set("X-CSRF-Token", "") }, status: 403},
		{name: "wrong csrf", mutate: func(r *http.Request) { r.Header.Set("X-CSRF-Token", "wrong") }, status: 403},
		{name: "missing organization", mutate: func(r *http.Request) { r.Header.Del("X-Organization-ID") }, status: 409},
		{name: "wrong revision", mutate: func(r *http.Request) { r.Header.Set("X-Organization-Revision", "2") }, status: 409},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			response := renewalRequest(a, cookie, csrf, testCase.mutate)
			if response.Code != testCase.status || len(response.Result().Cookies()) != 0 {
				t.Fatalf("HTTP %d cookies=%v body=%s", response.Code, response.Result().Cookies(), response.Body.String())
			}
			after := renewalReadSession(t, a, cookie)
			if !after.IdleUntil.Equal(before.IdleUntil) || !after.Until.Equal(before.Until) {
				t.Fatal("rejected request extended idle deadline")
			}
		})
	}
}

func TestSessionRenewalProviderAndRedisFailuresDoNotExtend(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		resource []string
	}{
		{name: "identity-only", resource: []string{""}},
		{name: "resource", resource: nil},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			a, f := fixtureRuntime(t, testCase.resource...)
			cookie := loginFixture(t, a, f)
			body := sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
			csrf := body["csrf_token"].(string)
			before := renewalReadSession(t, a, cookie)
			a.store.now = func() time.Time { return before.AuthenticatedAt.Add(time.Minute) }
			f.unavailable = true
			response := renewalRequest(a, cookie, csrf, nil)
			if response.Code != http.StatusServiceUnavailable || len(response.Result().Cookies()) != 0 {
				t.Fatalf("provider unavailable HTTP %d cookies=%v", response.Code, response.Result().Cookies())
			}
			after := renewalReadSession(t, a, cookie)
			if !after.IdleUntil.Equal(before.IdleUntil) || !after.Until.Equal(before.Until) {
				t.Fatal("provider failure extended idle deadline")
			}
		})
	}
}

func TestSessionRenewalRejectsChangedCentralIdentityWithoutExtension(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	body := sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
	csrf := body["csrf_token"].(string)
	before := renewalReadSession(t, a, cookie)
	a.store.now = func() time.Time { return before.AuthenticatedAt.Add(time.Minute) }
	f.revision = "2"
	response := renewalRequest(a, cookie, csrf, nil)
	if response.Code != http.StatusConflict || sessionBody(t, response)["error"] != "organization_identity_changed" || len(response.Result().Cookies()) != 0 {
		t.Fatalf("changed central identity HTTP %d cookies=%v body=%s", response.Code, response.Result().Cookies(), response.Body.String())
	}
	after := renewalReadSession(t, a, cookie)
	if after.Organization != before.Organization || after.Revision != before.Revision || !after.IdleUntil.Equal(before.IdleUntil) || !after.Until.Equal(before.Until) {
		t.Fatalf("renewal adopted changed identity or extended idle: before=%#v after=%#v", before, after)
	}
}

// renewalBoundaryDelayedCommit models bounded latency between computing the
// Redis TTL and executing SET. It does not alter the record or Redis clock.
type renewalBoundaryDelayedCommit struct{ armed atomic.Bool }

func (h *renewalBoundaryDelayedCommit) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (h *renewalBoundaryDelayedCommit) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (h *renewalBoundaryDelayedCommit) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "eval" && strings.Contains(cmd.String(), "ARGV[5]") && h.armed.CompareAndSwap(true, false) {
			time.Sleep(700 * time.Millisecond)
		}
		return next(ctx, cmd)
	}
}

func TestResourceRenewalRechecksOriginalIdleAfterOnlineIdentity(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			a, f := fixtureRuntime(t)
			cookie := loginFixture(t, a, f)
			body := sessionBody(t, callAuth(a, http.MethodGet, "/auth/session", "", cookie, ""))
			csrf := body["csrf_token"].(string)
			value, owner, err := a.store.acquire(context.Background(), cookie.Value)
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(2 * time.Second)
			value.IdleUntil, value.Until = deadline, deadline
			delay := &renewalBoundaryDelayedCommit{}
			a.store.db.AddHook(delay)
			delay.armed.Store(true)
			if err := a.store.commit(context.Background(), cookie.Value, owner, cookie.Value, value, false); err != nil {
				t.Fatal(err)
			}
			if delay.armed.Load() || !time.Now().Before(deadline) {
				t.Fatal("fixture did not cross setup with a still-valid original deadline")
			}
			base := a.http.Transport
			a.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/api/my-account/organization-identity" {
					time.Sleep(time.Until(deadline.Add(100 * time.Millisecond)))
				}
				return base.RoundTrip(r)
			})
			response := callAuth(a, method, "/auth/session", "{}", cookie, csrf)
			if time.Now().Before(deadline) {
				t.Fatal("online identity check did not cross original idle deadline")
			}
			if response.Code >= 200 && response.Code < 300 {
				stored := renewalReadSession(t, a, cookie)
				t.Fatalf("accepted expired original session: method=%s status=%d old_idle=%s stored_idle=%s", method, response.Code, deadline.Format(time.RFC3339Nano), stored.IdleUntil.Format(time.RFC3339Nano))
			}
		})
	}
}

func TestSessionRenewalRedisUnavailableDoesNotAlterStoredDeadline(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	body := sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
	csrf := body["csrf_token"].(string)
	before := renewalReadSession(t, a, cookie)
	a.store.now = func() time.Time { return before.AuthenticatedAt.Add(time.Minute) }
	original := a.store.db
	a.store.db = redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 20 * time.Millisecond, MaxRetries: -1})
	response := renewalRequest(a, cookie, csrf, nil)
	if response.Code != http.StatusServiceUnavailable || len(response.Result().Cookies()) != 0 {
		t.Fatalf("Redis unavailable HTTP %d cookies=%v", response.Code, response.Result().Cookies())
	}
	_ = a.store.db.Close()
	a.store.db = original
	after := renewalReadSession(t, a, cookie)
	if !after.IdleUntil.Equal(before.IdleUntil) || !after.Until.Equal(before.Until) {
		t.Fatal("Redis failure altered persisted deadline")
	}
}

func TestIdentityUpdateMergesRenewalButRejectsIdentityMutation(t *testing.T) {
	now := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	before := renewalPolicySession(now)
	current := renewalClone(t, before)
	current.IdleUntil = now.Add(10 * time.Hour)
	current.Until = current.IdleUntil
	current.SDK[client.StorageKeyRefreshToken] = "refresh-rotated"
	lateGET := renewalClone(t, before)
	lateGET.SDK[client.StorageKeyRefreshToken] = "refresh-stale"
	if err := mergeIdentityUpdate(current, before, lateGET, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !current.IdleUntil.Equal(now.Add(10*time.Hour)) || current.SDK[client.StorageKeyRefreshToken] != "refresh-rotated" {
		t.Fatal("late identity update clobbered renewed deadline or rotated SDK state")
	}
	earlierTouch := renewalClone(t, before)
	earlierTouch.IdleUntil = now.Add(9 * time.Hour)
	earlierTouch.Until = earlierTouch.IdleUntil
	if err := mergeIdentityUpdate(current, before, earlierTouch, now.Add(2*time.Minute)); err != nil || !current.IdleUntil.Equal(now.Add(10*time.Hour)) {
		t.Fatalf("two-touch merge rewound deadline: %v %s", err, current.IdleUntil)
	}
	rotated := renewalClone(t, before)
	rotated.Revision = "2"
	rotated.CSRF = "csrf-new"
	if err := mergeIdentityUpdate(rotated, before, lateGET, now.Add(time.Minute)); classify(err).status != http.StatusConflict {
		t.Fatalf("identity rotation was merged: %v", err)
	}
}

func TestFinishIdentityPreservesRenewalAndCannotReviveLogout(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	stale := renewalReadSession(t, a, cookie)
	current, owner, err := a.store.acquire(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	current.IdleUntil = stale.IdleUntil.Add(time.Hour)
	current.Until = current.IdleUntil
	current.SDK[client.StorageKeyRefreshToken] = "refresh-rotated"
	if err := a.store.commit(context.Background(), cookie.Value, owner, cookie.Value, current, false); err != nil {
		t.Fatal(err)
	}
	late := renewalClone(t, stale)
	late.SDK[client.StorageKeyRefreshToken] = "refresh-stale"
	if err := a.finishIdentity(context.Background(), cookie.Value, cookie.Value, stale, late, false); err != nil {
		t.Fatal(err)
	}
	merged := renewalReadSession(t, a, cookie)
	if !merged.IdleUntil.Equal(current.IdleUntil) || merged.SDK[client.StorageKeyRefreshToken] != "refresh-rotated" {
		t.Fatal("finishIdentity clobbered concurrent renewal or SDK rotation")
	}
	remove, removeOwner, err := a.store.acquire(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.store.commit(context.Background(), cookie.Value, removeOwner, cookie.Value, remove, true); err != nil {
		t.Fatal(err)
	}
	if err := a.finishIdentity(context.Background(), cookie.Value, cookie.Value, merged, renewalClone(t, merged), false); !errors.Is(err, _errMissing) {
		t.Fatalf("late update revived logout: %v", err)
	}
	if _, _, err := a.store.acquire(context.Background(), cookie.Value); !errors.Is(err, _errMissing) {
		t.Fatalf("logged-out session revived: %v", err)
	}
}

func TestLateSessionViewCannotClobberConcurrentRenewal(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	body := sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
	csrf := body["csrf_token"].(string)
	before := renewalReadSession(t, a, cookie)
	a.store.now = func() time.Time { return before.AuthenticatedAt.Add(time.Minute) }
	observer := observeIdentity(t, a, true)

	var (
		group     sync.WaitGroup
		touchCode int
		getCode   int
		getExpiry time.Time
		touchDone = make(chan struct{})
		getDone   = make(chan struct{})
	)
	group.Add(2)
	go func() {
		defer group.Done()
		defer close(touchDone)
		touchCode = renewalRequest(a, cookie, csrf, nil).Code
	}()
	select {
	case <-observer.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("touch did not reach online identity verification")
	}
	go func() {
		defer group.Done()
		defer close(getDone)
		response := callAuth(a, "GET", "/auth/session", "", cookie, "")
		getCode = response.Code
		if response.Code == http.StatusOK {
			getExpiry = renewalExpiresAt(t, sessionBody(t, response))
		}
	}()
	select {
	case <-observer.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("late GET did not reach online identity verification")
	}
	observer.release <- struct{}{}
	select {
	case <-touchDone:
	case <-time.After(3 * time.Second):
		t.Fatal("touch did not finish")
	}
	if touchCode != http.StatusOK {
		t.Fatalf("touch HTTP %d", touchCode)
	}
	observer.release <- struct{}{}
	select {
	case <-getDone:
	case <-time.After(3 * time.Second):
		t.Fatal("late GET did not finish")
	}
	group.Wait()
	wantIdle := before.AuthenticatedAt.Add(time.Minute + sessionIdleLifetime)
	after := renewalReadSession(t, a, cookie)
	if getCode != http.StatusOK || getExpiry.Unix() != wantIdle.Unix() || !after.IdleUntil.Equal(wantIdle) || !after.Until.Equal(wantIdle) {
		t.Fatalf("late GET rolled back renewal: HTTP %d response=%s stored=%s want=%s", getCode, getExpiry, after.IdleUntil, wantIdle)
	}
}

func TestRenewalRejectsStaleCookieWithoutReplacingCurrentSession(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	oldCookie := loginFixture(t, a, f)
	f.revision = "2"
	rotated := callAuth(a, "GET", "/auth/session", "", oldCookie, "")
	if rotated.Code != http.StatusOK || len(rotated.Result().Cookies()) != 1 {
		t.Fatalf("identity rotation failed: HTTP %d", rotated.Code)
	}
	newCookie := rotated.Result().Cookies()[0]
	response := renewalRequest(a, oldCookie, "stale-csrf", nil)
	if response.Code != http.StatusUnauthorized || len(response.Result().Cookies()) != 0 {
		t.Fatalf("stale touch HTTP %d cookies=%v body=%s", response.Code, response.Result().Cookies(), response.Body.String())
	}
	if got := callAuth(a, "GET", "/auth/session", "", newCookie, ""); got.Code != http.StatusOK {
		t.Fatal("stale touch invalidated the current rotated cookie")
	}
}
