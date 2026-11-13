package logtobff

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// TestReadBeginMissingKeepsWireContract verifies an absent session retains each mode's public error.
func TestReadBeginMissingKeepsWireContract(t *testing.T) {
	runReadBeginRoutes(t, func(t *testing.T, a *Runtime, cookie *http.Cookie, original *session, route string) {
		cookie.Value = testOpaque(t)
		response := callReadBeginRoute(t, a, cookie, original.CSRF, route)
		assertReadBeginResponse(t, a, response, http.StatusUnauthorized, "session_expired", false /* clearResource */)
	})
}

// TestReadBeginInvalidKeepsWireContract verifies invalid stored schema is rejected before online checks.
func TestReadBeginInvalidKeepsWireContract(t *testing.T) {
	runReadBeginRoutes(t, func(t *testing.T, a *Runtime, cookie *http.Cookie, original *session, route string) {
		invalid := renewalClone(t, original)
		invalid.PolicyVersion = 0
		storeReadBeginSession(t, a, cookie, invalid)
		response := callReadBeginRoute(t, a, cookie, original.CSRF, route)
		assertReadBeginResponse(t, a, response, http.StatusUnauthorized, "session_invalid", false /* clearResource */)
	})
}

// TestReadBeginStoreFailureKeepsWireContract verifies acquisition failures preserve the original store error.
func TestReadBeginStoreFailureKeepsWireContract(t *testing.T) {
	runReadBeginRoutes(t, func(t *testing.T, a *Runtime, cookie *http.Cookie, original *session, route string) {
		a.store.db.AddHook(&readBeginFailureHook{failAt: 1})
		response := callReadBeginRoute(t, a, cookie, original.CSRF, route)
		assertReadBeginResponse(t, a, response, http.StatusServiceUnavailable, "session_store_unavailable", false /* clearResource */)
	})
}

// TestReadBeginPreparationRejectionOwnsCookie verifies only a committed resource preparation can clear its cookie.
func TestReadBeginPreparationRejectionOwnsCookie(t *testing.T) {
	runReadBeginRoutes(t, func(t *testing.T, a *Runtime, cookie *http.Cookie, original *session, route string) {
		invalid := renewalClone(t, original)
		invalid.SDK = nil
		storeReadBeginSession(t, a, cookie, invalid)
		response := callReadBeginRoute(t, a, cookie, original.CSRF, route)
		assertReadBeginResponse(t, a, response, http.StatusUnauthorized, "session_invalid", true /* clearResource */)
		_, owner, err := a.store.acquire(context.Background(), cookie.Value)
		if err == nil {
			a.store.release(context.Background(), cookie.Value, owner)
		}
		if !errors.Is(err, _errMissing) {
			t.Fatal("committed preparation rejection retained the session")
		}
	})
}

// TestReadBeginCommitFailureKeepsWireContract verifies an uncertain resource commit remains a non-revoking 503.
func TestReadBeginCommitFailureKeepsWireContract(t *testing.T) {
	runReadBeginRoutes(t, func(t *testing.T, a *Runtime, cookie *http.Cookie, original *session, route string) {
		a.store.db.AddHook(&readBeginFailureHook{failAt: 2})
		response := callReadBeginRoute(t, a, cookie, original.CSRF, route)
		assertReadBeginResponse(t, a, response, http.StatusServiceUnavailable, "session_commit_failed", false /* clearResource */)
	})
}

// runReadBeginRoutes owns fresh fixtures for two modes and two real routes.
// Each caller supplies one straight-line failure scenario and its assertions.
func runReadBeginRoutes(t *testing.T, check func(*testing.T, *Runtime, *http.Cookie, *session, string)) {
	t.Helper()
	tests := []struct{ name, resource string }{
		{name: "resource", resource: "https://credits.invalid/api"},
		{name: "identity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, route := range []string{"session", "protected"} {
				t.Run(route, func(t *testing.T) {
					var (
						a, authority = fixtureRuntime(t, tt.resource)
						cookie       = loginFixture(t, a, authority)
						original     = renewalReadSession(t, a, cookie)
					)
					check(t, a, cookie, original, route)
				})
			}
		})
	}
}

// assertReadBeginResponse checks the same response shape for every failure.
// Cookie clearing is expected only when the caller names committed preparation.
func assertReadBeginResponse(t *testing.T, a *Runtime, response *httptest.ResponseRecorder, status int, resourceCode string, clearResource bool) {
	t.Helper()
	code := resourceCode
	if a.config.APIResource == "" {
		code = "session_unavailable"
	}
	wantBody := `{"error":"` + code + `"}` + "\n"
	if response.Code != status || response.Body.String() != wantBody {
		t.Fatalf("begin failure HTTP %d body %s, want %d/%s", response.Code, response.Body.String(), status, code)
	}
	cookies := response.Result().Cookies()
	if clearResource && a.config.APIResource != "" {
		if len(cookies) != 1 || cookies[0].Name != a.config.CookieName || cookies[0].Value != "" || cookies[0].MaxAge >= 0 {
			t.Fatal("committed resource preparation did not revoke only the original cookie")
		}
	} else if len(cookies) != 0 {
		t.Fatal("begin failure changed cookie revocation ownership")
	}
}

// storeReadBeginSession replaces only this owned fixture's encrypted session.
func storeReadBeginSession(t *testing.T, a *Runtime, cookie *http.Cookie, value *session) {
	t.Helper()
	var (
		key       = a.store.prefix + "s:" + cookie.Value
		data, err = a.store.seal(key, value)
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.store.db.Set(context.Background(), key, data, time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
}

// TestBeginIdentityFailurePreservesCause verifies real begin failures still
// support sentinel and typed-error matching through the private stage wrapper.
func TestBeginIdentityFailurePreservesCause(t *testing.T) {
	a, authority := fixtureRuntime(t)
	if _, err := a.beginIdentity(context.Background(), testOpaque(t)); !errors.Is(err, _errMissing) {
		t.Fatal("begin acquisition lost its matchable missing-session cause")
	}
	var (
		cookie = loginFixture(t, a, authority)
		value  = renewalReadSession(t, a, cookie)
	)
	value.SDK = nil
	storeReadBeginSession(t, a, cookie, value)
	var rejected *accessError
	if _, err := a.beginIdentity(context.Background(), cookie.Value); !errors.As(err, &rejected) || rejected.status != http.StatusUnauthorized || rejected.code != "session_invalid" {
		t.Fatal("committed begin preparation lost its typed rejection cause")
	}
}

// callReadBeginRoute reaches the real auth middleware and refuses any business
// invocation, so an error response cannot hide an earlier authorization leak.
func callReadBeginRoute(t *testing.T, a *Runtime, cookie *http.Cookie, csrf, route string) *httptest.ResponseRecorder {
	t.Helper()
	if route == "session" {
		return callAuth(a, http.MethodGet, "/auth/session", "", cookie, "")
	}
	router := gin.New()
	router.POST("/protected", a.Require(), func(c *gin.Context) {
		t.Error("begin failure reached the protected business handler")
		c.Status(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodPost, a.config.Origin+"/protected", nil)
	request.AddCookie(cookie)
	request.Header.Set("Origin", a.config.Origin)
	request.Header.Set("X-CSRF-Token", csrf)
	request.Header.Set("X-Organization-ID", "org-one")
	request.Header.Set("X-Organization-Revision", "1")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// readBeginFailureHook rejects one selected EVAL in the owned Redis fixture.
// No provider, credentials or external database are involved.
type readBeginFailureHook struct {
	failAt int64
	calls  atomic.Int64
}

// DialHook preserves the fixture client's connection hook chain.
func (*readBeginFailureHook) DialHook(next redis.DialHook) redis.DialHook { return next }

// ProcessPipelineHook preserves the fixture client's pipeline hook chain.
func (*readBeginFailureHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// ProcessHook injects exactly one acquire or commit failure, leaving release
// and subsequent inspection available to the assertion.
func (h *readBeginFailureHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, command redis.Cmder) error {
		if command.Name() == "eval" && h.calls.Add(1) == h.failAt {
			return errors.New("synthetic begin session store failure")
		}
		return next(ctx, command)
	}
}
