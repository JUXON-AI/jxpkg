package logtobff

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// pendingResourceRead owns one blocked synthetic request and its joined cleanup.
type pendingResourceRead struct {
	runtime       *Runtime
	authority     *fakeAuthority
	cookie        *http.Cookie
	original      *session
	release       chan struct{}
	result        chan int
	businessCalls atomic.Int64
	releaseOnce   sync.Once
}

// TestResourceSessionParallelOnlineChecks verifies a slow authority read does
// not serialize other reads. Authority and Redis contain only synthetic data.
func TestResourceSessionParallelOnlineChecks(t *testing.T) {
	for _, route := range []string{"session", "protected"} {
		t.Run(route, func(t *testing.T) {
			var (
				a, authority = fixtureRuntime(t)
				cookie       = loginFixture(t, a, authority)
				body         = sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
				csrf, ok     = body["csrf_token"].(string)
			)
			if !ok || csrf == "" {
				t.Fatal("resource fixture session is missing its CSRF token")
			}
			router := gin.New()
			router.POST("/protected", a.Require("read:credits"), func(c *gin.Context) {
				principal, ok := FromContext(c.Request.Context())
				if !ok || principal.OrganizationID != "org-one" || !slices.Contains(principal.Permissions, "read:credits") {
					t.Error("parallel read lost its verified resource authority")
				}
				if principal.ExpiresAt > time.Now().Add(5*time.Minute).Unix() || principal.ExpiresAt < time.Now().Add(4*time.Minute).Unix() {
					t.Error("session deadline extended the five-minute resource credential")
				}
				c.Status(http.StatusNoContent)
			})
			var (
				observer  = observeIdentity(t, a, true /* block */)
				pending   sync.WaitGroup
				responses = make(chan int, 2)
			)
			defer func() { close(observer.release); pending.Wait() }()
			for range 2 {
				pending.Go(func() {
					if route == "session" {
						responses <- callAuth(a, "GET", "/auth/session", "", cookie, "").Code
						return
					}
					request := httptest.NewRequest("POST", a.config.Origin+"/protected", nil)
					request.AddCookie(cookie)
					request.Header.Set("Origin", a.config.Origin)
					request.Header.Set("X-CSRF-Token", csrf)
					request.Header.Set("X-Organization-ID", "org-one")
					request.Header.Set("X-Organization-Revision", "1")
					response := httptest.NewRecorder()
					router.ServeHTTP(response, request)
					responses <- response.Code
				})
			}
			for range 2 {
				select {
				case <-observer.entered:
				case <-time.After(3 * time.Second):
					t.Fatal("resource authority reads serialized behind the session lease")
				}
			}
			observer.release <- struct{}{}
			observer.release <- struct{}{}
			pending.Wait()
			want := http.StatusOK
			if route == "protected" {
				want = http.StatusNoContent
			}
			for range 2 {
				if got := <-responses; got != want {
					t.Fatalf("parallel unchanged resource session status = %d, want %d", got, want)
				}
			}
		})
	}
}

// TestResourcePrincipalRespectsEarlierSessionDeadline covers the session side
// of the credential/session expiry minimum.
func TestResourcePrincipalRespectsEarlierSessionDeadline(t *testing.T) {
	var (
		a, authority      = fixtureRuntime(t)
		cookie            = loginFixture(t, a, authority)
		value, owner, err = a.store.acquire(context.Background(), cookie.Value)
	)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	value.IdleUntil, value.Until = deadline, deadline
	if err := a.store.commit(context.Background(), cookie.Value, owner, cookie.Value, value, false /* remove */); err != nil {
		t.Fatal(err)
	}
	var (
		router = gin.New()
		hits   = 0
	)
	router.POST("/protected", a.Require("read:credits"), func(c *gin.Context) {
		principal, ok := FromContext(c.Request.Context())
		if !ok || principal.ExpiresAt != deadline.Unix() {
			t.Error("resource principal outlived the earlier session deadline")
		}
		hits++
		c.Status(http.StatusNoContent)
	})
	request := httptest.NewRequest("POST", a.config.Origin+"/protected", nil)
	request.AddCookie(cookie)
	request.Header.Set("Origin", a.config.Origin)
	request.Header.Set("X-CSRF-Token", value.CSRF)
	request.Header.Set("X-Organization-ID", "org-one")
	request.Header.Set("X-Organization-Revision", "1")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || hits != 1 {
		t.Fatalf("bounded resource principal HTTP %d, business calls %d", response.Code, hits)
	}
}

// TestResourceReadRejectsLogoutDuringOnlineCheck prevents a pending read from reviving logout.
func TestResourceReadRejectsLogoutDuringOnlineCheck(t *testing.T) {
	var (
		pending             = startPendingResourceRead(t)
		current, owner, err = pending.runtime.store.acquire(context.Background(), pending.cookie.Value)
	)
	if err != nil {
		t.Fatal(err)
	}
	current.Revision = "2"
	if err := pending.runtime.store.commit(context.Background(), pending.cookie.Value, owner, pending.cookie.Value, current, true /* remove */); err != nil {
		t.Fatal(err)
	}
	pending.finish(t, http.StatusUnauthorized)
	_, owner, err = pending.runtime.store.acquire(context.Background(), pending.cookie.Value)
	if err == nil {
		pending.runtime.store.release(context.Background(), pending.cookie.Value, owner)
	}
	if !errors.Is(err, _errMissing) {
		t.Fatal("pending read recreated a logged-out session")
	}
}

// TestResourceReadRejectsRevisionDuringOnlineCheck prevents an old read from rewinding identity.
func TestResourceReadRejectsRevisionDuringOnlineCheck(t *testing.T) {
	var (
		pending             = startPendingResourceRead(t)
		current, owner, err = pending.runtime.store.acquire(context.Background(), pending.cookie.Value)
	)
	if err != nil {
		t.Fatal(err)
	}
	current.Revision = "2"
	if err := pending.runtime.store.commit(context.Background(), pending.cookie.Value, owner, pending.cookie.Value, current, false /* remove */); err != nil {
		t.Fatal(err)
	}
	pending.finish(t, http.StatusConflict)
	if current := renewalReadSession(t, pending.runtime, pending.cookie); current.Revision != "2" {
		t.Fatal("pending read rewound the selected identity")
	}
}

// TestResourceReadRejectsScopeRevocationDuringOnlineCheck requires current resource permissions.
func TestResourceReadRejectsScopeRevocationDuringOnlineCheck(t *testing.T) {
	pending := startPendingResourceRead(t)
	pending.authority.readOnly = true
	pending.finish(t, http.StatusForbidden)
}

// TestResourceReadRejectsStaleFailureAfterSDKRefresh preserves a newer SDK after a late identity failure.
func TestResourceReadRejectsStaleFailureAfterSDKRefresh(t *testing.T) {
	var (
		pending = startPendingResourceRead(t)
		rotated = rotateStoredSDK(t, pending.runtime, pending.cookie, "synthetic-concurrent-resource-refresh")
	)
	pending.authority.identityInvalid = true
	pending.finish(t, http.StatusConflict)
	assertConcurrentSDKPreserved(t, pending.runtime, pending.cookie, pending.original.CSRF, rotated)
}

// startPendingResourceRead starts one real protected route and blocks its online identity read.
func startPendingResourceRead(t *testing.T) *pendingResourceRead {
	t.Helper()
	var (
		a, authority = fixtureRuntime(t)
		cookie       = loginFixture(t, a, authority)
		original     = renewalReadSession(t, a, cookie)
		router       = gin.New()
		pending      = &pendingResourceRead{runtime: a, authority: authority, cookie: cookie, original: original}
	)
	router.POST("/protected", a.Require("manage:credits"), func(c *gin.Context) {
		pending.businessCalls.Add(1)
		c.Status(http.StatusNoContent)
	})
	observer := observeIdentity(t, a, true /* block */)
	pending.release = observer.release
	pending.result = make(chan int, 1)
	// This cleanup runs before fixtureRuntime closes the BFF and its Redis client.
	t.Cleanup(func() {
		pending.unblock()
		for range pending.result {
		}
	})
	go func() {
		defer close(pending.result)
		request := httptest.NewRequest(http.MethodPost, a.config.Origin+"/protected", nil)
		request.AddCookie(cookie)
		request.Header.Set("Origin", a.config.Origin)
		request.Header.Set("X-CSRF-Token", original.CSRF)
		request.Header.Set("X-Organization-ID", "org-one")
		request.Header.Set("X-Organization-Revision", "1")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		pending.result <- response.Code
	}()
	waitForAuthority(t, observer.entered)
	return pending
}

// finish releases the authority gate and verifies rejection before business dispatch.
func (p *pendingResourceRead) finish(t *testing.T, status int) {
	t.Helper()
	p.unblock()
	if got := <-p.result; got != status || p.businessCalls.Load() != 0 {
		t.Fatalf("pending resource read HTTP %d, want %d, business calls %d", got, status, p.businessCalls.Load())
	}
}

// unblock releases the request once, whether assertions or test cleanup finish first.
func (p *pendingResourceRead) unblock() {
	p.releaseOnce.Do(func() { close(p.release) })
}
