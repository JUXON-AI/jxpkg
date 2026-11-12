package logtobff

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// TestResourceSessionParallelOnlineChecks verifies a slow authority read does
// not serialize other reads. Authority and Redis contain only synthetic data.
func TestResourceSessionParallelOnlineChecks(t *testing.T) {
	for _, route := range []string{"session", "protected"} {
		t.Run(route, func(t *testing.T) {
			a, authority := fixtureRuntime(t)
			cookie := loginFixture(t, a, authority)
			body := sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
			csrf, ok := body["csrf_token"].(string)
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
			observer := observeIdentity(t, a, true)
			var pending sync.WaitGroup
			responses := make(chan int, 2)
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
	a, authority := fixtureRuntime(t)
	cookie := loginFixture(t, a, authority)
	value, owner, err := a.store.acquire(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	value.IdleUntil, value.Until = deadline, deadline
	if err := a.store.commit(context.Background(), cookie.Value, owner, cookie.Value, value, false); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	hits := 0
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

// TestResourceReadRejectsChangesDuringOnlineCheck keeps pending reads subject to
// current logout, identity, permission and SDK state.
func TestResourceReadRejectsChangesDuringOnlineCheck(t *testing.T) {
	for _, change := range []string{"logout", "revision", "scope", "sdk_then_invalid"} {
		t.Run(change, func(t *testing.T) {
			a, authority := fixtureRuntime(t)
			cookie := loginFixture(t, a, authority)
			original := renewalReadSession(t, a, cookie)
			router := gin.New()
			hits := 0
			router.POST("/protected", a.Require("manage:credits"), func(c *gin.Context) { hits++; c.Status(http.StatusNoContent) })
			observer := observeIdentity(t, a, true)
			done := make(chan int, 1)
			go func() {
				defer close(done)
				request := httptest.NewRequest("POST", a.config.Origin+"/protected", nil)
				request.AddCookie(cookie)
				request.Header.Set("Origin", a.config.Origin)
				request.Header.Set("X-CSRF-Token", original.CSRF)
				request.Header.Set("X-Organization-ID", "org-one")
				request.Header.Set("X-Organization-Revision", "1")
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				done <- response.Code
			}()
			defer func() {
				close(observer.release)
				for range done {
				}
			}()
			waitForAuthority(t, observer.entered)
			want := http.StatusConflict
			var rotated *session
			switch change {
			case "scope":
				authority.readOnly = true
				want = http.StatusForbidden
			case "sdk_then_invalid":
				rotated = rotateStoredSDK(t, a, cookie, "synthetic-concurrent-resource-refresh")
				authority.identityInvalid = true
			default:
				current, owner, err := a.store.acquire(context.Background(), cookie.Value)
				if err != nil {
					t.Fatal(err)
				}
				current.Revision = "2"
				if err := a.store.commit(context.Background(), cookie.Value, owner, cookie.Value, current, change == "logout"); err != nil {
					t.Fatal(err)
				}
				if change == "logout" {
					want = http.StatusUnauthorized
				}
			}
			observer.release <- struct{}{}
			if got := <-done; got != want || hits != 0 {
				t.Fatalf("pending %s read HTTP %d, want %d, business calls %d", change, got, want, hits)
			}
			switch change {
			case "logout":
				if _, _, err := a.store.acquire(context.Background(), cookie.Value); !errors.Is(err, _errMissing) {
					t.Fatal("pending read recreated a logged-out session")
				}
			case "revision":
				if current := renewalReadSession(t, a, cookie); current.Revision != "2" {
					t.Fatal("pending read rewound the selected identity")
				}
			case "sdk_then_invalid":
				assertConcurrentSDKPreserved(t, a, cookie, original.CSRF, rotated)
			}
		})
	}
}
