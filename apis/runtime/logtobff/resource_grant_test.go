package logtobff

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/requestid"
	"github.com/gin-gonic/gin"
	"github.com/logto-io/go/v2/client"
	"github.com/redis/go-redis/v9"
)

func TestRevokeResourceGrantRequiresBrowserSessionCapability(t *testing.T) {
	if err := RevokeResourceGrant(context.Background(), "https://hub.invalid/mcp", "grant-one"); !errors.Is(err, ErrAuthorizationChanged) {
		t.Fatalf("missing capability error = %v", err)
	}
	forged := &forgedRevokeContext{}
	if err := RevokeResourceGrant(forged, "https://hub.invalid/mcp", "grant-one"); !errors.Is(err, ErrAuthorizationChanged) || forged.calls != 0 {
		t.Fatalf("forged public function error=%v calls=%d", err, forged.calls)
	}
}

type forgedRevokeContext struct{ calls int }

func (*forgedRevokeContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*forgedRevokeContext) Done() <-chan struct{}       { return nil }
func (*forgedRevokeContext) Err() error                  { return nil }
func (c *forgedRevokeContext) Value(any) any {
	return func(context.Context, string, string) error {
		c.calls++
		return nil
	}
}

func TestGrantResourceLoopbackAllowlist(t *testing.T) {
	for value, valid := range map[string]bool{
		"https://hub.invalid/mcp":     true,
		"http://localhost:5180/mcp":   true,
		"http://127.0.0.1:5180/mcp":   true,
		"http://[::1]:5180/mcp":       true,
		"http://127.0.0.2:5180/mcp":   false,
		"http://0.0.0.0:5180/mcp":     false,
		"http://hub.invalid/mcp":      false,
		"https://hub.invalid/not-mcp": true,
	} {
		if got := validGrantResource(value); got != valid {
			t.Errorf("validGrantResource(%q)=%t, want %t", value, got, valid)
		}
	}
}

func TestRevokeResourceGrantRevalidatesAndCommitsRotation(t *testing.T) {
	var (
		a, f      = fixtureRuntime(t)
		cookie    = loginFixture(t, a, f)
		csrf      = sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
		before    = storedSDKCredentials(t, a, cookie)
		refreshes = f.refreshes
	)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/revoke", a.Require(), func(c *gin.Context) {
		value, owner, err := a.store.acquire(c.Request.Context(), cookie.Value)
		if err != nil {
			t.Error(err)
			c.Status(http.StatusInternalServerError)
			return
		}
		defer a.store.release(context.WithoutCancel(c.Request.Context()), cookie.Value, owner)
		var tokens map[string]client.AccessToken
		if err := json.Unmarshal([]byte(value.SDK[client.StorageKeyAccessTokenMap]), &tokens); err != nil {
			t.Error(err)
			c.Status(http.StatusInternalServerError)
			return
		}
		for key, token := range tokens {
			token.ExpiresAt = 1
			tokens[key] = token
		}
		encoded, err := json.Marshal(tokens)
		if err != nil {
			t.Error(err)
			c.Status(http.StatusInternalServerError)
			return
		}
		value.SDK[client.StorageKeyAccessTokenMap] = string(encoded)
		if err := a.store.commit(c.Request.Context(), cookie.Value, owner, cookie.Value, value, false); err != nil {
			t.Error(err)
			c.Status(http.StatusInternalServerError)
			return
		}
		if err := RevokeResourceGrant(c.Request.Context(), "https://hub.invalid/mcp", strings.Repeat("g", 128)); err != nil {
			t.Errorf("revoke failed: %v", err)
			c.Status(http.StatusServiceUnavailable)
			return
		}
		c.Status(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodPost, a.config.Origin+"/revoke", nil)
	request.AddCookie(cookie)
	request.Header.Set("Origin", a.config.Origin)
	request.Header.Set("X-CSRF-Token", csrf)
	request.Header.Set("X-Organization-ID", "org-one")
	request.Header.Set("X-Organization-Revision", "1")
	request.Header.Set("X-Request-ID", "revoke-request")
	request = request.WithContext(requestid.WithContext(request.Context(), "revoke-request"))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || f.resourceRevokeCalls != 1 {
		t.Fatalf("response=%d calls=%d", response.Code, f.resourceRevokeCalls)
	}
	if f.resourceRevokeAuthorization != "Bearer opaque-account-access" || f.resourceRevokeRequestID != "revoke-request" {
		t.Fatal("private token or request identity not propagated")
	}
	var body resourceGrantRevokeRequest
	if err := json.Unmarshal([]byte(f.resourceRevokeBody), &body); err != nil {
		t.Fatal(err)
	}
	if body.Resource != "https://hub.invalid/mcp" || body.GrantID != strings.Repeat("g", 128) || body.OrganizationID != "org-one" || body.ExpectedRevision != "1" {
		t.Fatal("wire body changed")
	}
	if f.refreshes <= refreshes {
		t.Fatal("call-time revalidation did not rotate credentials")
	}
	after := storedSDKCredentials(t, a, cookie)
	if after[client.StorageKeyRefreshToken] == before[client.StorageKeyRefreshToken] || after[client.StorageKeyRefreshToken] == "" {
		t.Fatal("rotated SDK state was not committed before success")
	}
}

// TestRevokeResourceGrantRotationCommitFailureReleasesLease verifies a failed
// fixture commit cannot leave the session lock behind.
func TestRevokeResourceGrantRotationCommitFailureReleasesLease(t *testing.T) {
	var (
		a, f               = fixtureRuntime(t)
		cookie             = loginFixture(t, a, f)
		csrf               = sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
		fault              = &rotationCommitFailureHook{}
		callbackEntered    bool
		targetCommitFailed bool
	)
	a.store.db.AddHook(fault)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/revoke", a.Require(), func(c *gin.Context) {
		callbackEntered = true
		value, owner, err := a.store.acquire(c.Request.Context(), cookie.Value)
		if err != nil {
			t.Error(err)
			c.Status(http.StatusInternalServerError)
			return
		}
		defer a.store.release(context.WithoutCancel(c.Request.Context()), cookie.Value, owner)
		var tokens map[string]client.AccessToken
		if err := json.Unmarshal([]byte(value.SDK[client.StorageKeyAccessTokenMap]), &tokens); err != nil {
			t.Error(err)
			c.Status(http.StatusInternalServerError)
			return
		}
		for key, token := range tokens {
			token.ExpiresAt = 1
			tokens[key] = token
		}
		encoded, err := json.Marshal(tokens)
		if err != nil {
			t.Error(err)
			c.Status(http.StatusInternalServerError)
			return
		}
		value.SDK[client.StorageKeyAccessTokenMap] = string(encoded)
		fault.armed.Store(true)
		if err := a.store.commit(c.Request.Context(), cookie.Value, owner, cookie.Value, value, false); err == nil {
			t.Error("synthetic fixture commit failure was not injected")
		} else {
			targetCommitFailed = true
		}
		c.Status(http.StatusServiceUnavailable)
	})
	request := httptest.NewRequest(http.MethodPost, a.config.Origin+"/revoke", nil)
	request.AddCookie(cookie)
	request.Header.Set("Origin", a.config.Origin)
	request.Header.Set("X-CSRF-Token", csrf)
	request.Header.Set("X-Organization-ID", "org-one")
	request.Header.Set("X-Organization-Revision", "1")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !callbackEntered || !targetCommitFailed || !fault.failed.Load() || f.resourceRevokeCalls != 0 {
		t.Fatalf("response=%d callback_entered=%t target_commit_failed=%t fault_injected=%t remote_calls=%d", response.Code, callbackEntered, targetCommitFailed, fault.failed.Load(), f.resourceRevokeCalls)
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if remaining, err := a.store.db.Exists(cleanupCtx, a.store.prefix+"lock:"+cookie.Value).Result(); err != nil || remaining != 0 {
		t.Fatalf("target callback lease count=%d lookup_failed=%t", remaining, err != nil)
	}
	_, owner, err := a.store.acquire(cleanupCtx, cookie.Value)
	if err != nil {
		t.Fatalf("failed rotation retained lease: %v", err)
	}
	a.store.release(cleanupCtx, cookie.Value, owner)
}

type rotationCommitFailureHook struct {
	armed  atomic.Bool
	failed atomic.Bool
}

// DialHook preserves the Redis client's connection hook chain.
func (*rotationCommitFailureHook) DialHook(next redis.DialHook) redis.DialHook { return next }

// ProcessPipelineHook preserves the Redis client's pipeline hook chain.
func (*rotationCommitFailureHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// ProcessHook fails the explicitly armed fixture commit after Require has completed.
func (h *rotationCommitFailureHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, command redis.Cmder) error {
		if command.Name() == "eval" && h.armed.Load() && h.failed.CompareAndSwap(false, true) {
			return errors.New("synthetic rotation fixture commit failure")
		}
		return next(ctx, command)
	}
}

func TestRevokeResourceGrantFailsClosedOnRevisionOrDependencyChange(t *testing.T) {
	for _, test := range []struct {
		name       string
		change     func(*Runtime, *fakeAuthority, *http.Request) error
		wantErr    error
		wantStatus int
	}{
		{name: "revision", wantErr: ErrAuthorizationChanged, wantStatus: http.StatusConflict, change: func(a *Runtime, _ *fakeAuthority, r *http.Request) error {
			cookie, err := r.Cookie(a.config.CookieName)
			if err != nil {
				return err
			}
			value, owner, err := a.store.acquire(r.Context(), cookie.Value)
			if err != nil {
				return err
			}
			defer a.store.release(r.Context(), cookie.Value, owner)
			value.Revision = "2"
			return a.store.commit(r.Context(), cookie.Value, owner, cookie.Value, value, false)
		}},
		{name: "dependency", wantErr: ErrUnavailable, wantStatus: http.StatusServiceUnavailable, change: func(_ *Runtime, f *fakeAuthority, _ *http.Request) error {
			f.unavailable = true
			return nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var (
				a, f   = fixtureRuntime(t)
				cookie = loginFixture(t, a, f)
				csrf   = sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
				router = gin.New()
			)
			router.POST("/revoke", a.Require(), func(c *gin.Context) {
				if err := test.change(a, f, c.Request); err != nil {
					t.Errorf("change fixture: %v", err)
					c.Status(http.StatusInternalServerError)
					return
				}
				err := RevokeResourceGrant(c.Request.Context(), "https://hub.invalid/mcp", "grant-one")
				if !errors.Is(err, test.wantErr) {
					t.Errorf("error = %v", err)
				}
				c.Status(test.wantStatus)
			})
			request := httptest.NewRequest(http.MethodPost, a.config.Origin+"/revoke", nil)
			request.AddCookie(cookie)
			request.Header.Set("Origin", a.config.Origin)
			request.Header.Set("X-CSRF-Token", csrf)
			request.Header.Set("X-Organization-ID", "org-one")
			request.Header.Set("X-Organization-Revision", "1")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.wantStatus || f.resourceRevokeCalls != 0 {
				t.Fatalf("status=%d remote calls=%d", response.Code, f.resourceRevokeCalls)
			}
		})
	}
}

type closeErrorBody struct{ closed *atomic.Bool }

func (closeErrorBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b closeErrorBody) Close() error {
	b.closed.Store(true)
	return io.ErrUnexpectedEOF
}

type readErrorBody struct{ closed *atomic.Bool }

func (readErrorBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (b readErrorBody) Close() error {
	b.closed.Store(true)
	return io.ErrUnexpectedEOF
}

func TestRevokeAtAccountHandlesBodyCloseWithoutOverwritingStatus(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  int
		readErr bool
		wantErr error
	}{
		{name: "confirmed 204", status: http.StatusNoContent},
		{name: "authorization changed", status: http.StatusConflict, wantErr: ErrAuthorizationChanged},
		{name: "read failure wins", status: http.StatusNoContent, readErr: true, wantErr: ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			var (
				closed    atomic.Bool
				transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
					var body io.ReadCloser = closeErrorBody{closed: &closed}
					if test.readErr {
						body = readErrorBody{closed: &closed}
					}
					return &http.Response{
						StatusCode: test.status, Header: make(http.Header), Body: body,
						Request: request, ContentLength: 0,
					}, nil
				})
				runtime = &Runtime{
					config: Config{Endpoint: "https://account.invalid"},
					http:   &http.Client{Transport: transport},
				}
				err = runtime.revokeAtAccount(context.Background(), "token", resourceGrantRevokeRequest{Resource: "https://hub.invalid/mcp", GrantID: "grant"})
			)
			if !errors.Is(err, test.wantErr) || !closed.Load() {
				t.Fatalf("error=%v closed=%t", err, closed.Load())
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestRevokeResourceGrantNoRedirectOrSuccessOnUnknownStatus(t *testing.T) {
	for _, status := range []int{301, 302, 307, 400, 404, 409, 500, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var (
				a, f   = fixtureRuntime(t)
				cookie = loginFixture(t, a, f)
				csrf   = sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
			)
			f.resourceRevokeStatus = status
			router := gin.New()
			router.POST("/revoke", a.Require(), func(c *gin.Context) {
				err := RevokeResourceGrant(c.Request.Context(), "https://hub.invalid/mcp", "grant-one")
				if status == http.StatusConflict && !errors.Is(err, ErrAuthorizationChanged) || status != http.StatusConflict && !errors.Is(err, ErrUnavailable) {
					t.Errorf("status=%d error=%v", status, err)
				}
				c.Status(http.StatusServiceUnavailable)
			})
			request := httptest.NewRequest(http.MethodPost, a.config.Origin+"/revoke", nil)
			request.AddCookie(cookie)
			request.Header.Set("Origin", a.config.Origin)
			request.Header.Set("X-CSRF-Token", csrf)
			request.Header.Set("X-Organization-ID", "org-one")
			request.Header.Set("X-Organization-Revision", "1")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable || f.resourceRevokeCalls != 1 || f.endSessionCalls != 0 {
				t.Fatalf("status=%d response=%d calls=%d redirects=%d", status, response.Code, f.resourceRevokeCalls, f.endSessionCalls)
			}
		})
	}
}

func TestRevokeResourceGrantDoesNotAdoptChangedOrganizationInPlace(t *testing.T) {
	var (
		a, f   = fixtureRuntime(t)
		cookie = loginFixture(t, a, f)
		csrf   = sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
		router = gin.New()
	)
	router.POST("/revoke", a.Require(), func(c *gin.Context) {
		f.organization, f.revision = "org-two", "2"
		if err := RevokeResourceGrant(c.Request.Context(), "https://hub.invalid/mcp", "grant-one"); !errors.Is(err, ErrAuthorizationChanged) {
			t.Errorf("changed organization error = %v", err)
		}
		c.Status(http.StatusConflict)
	})
	request := httptest.NewRequest(http.MethodPost, a.config.Origin+"/revoke", nil)
	request.AddCookie(cookie)
	request.Header.Set("Origin", a.config.Origin)
	request.Header.Set("X-CSRF-Token", csrf)
	request.Header.Set("X-Organization-ID", "org-one")
	request.Header.Set("X-Organization-Revision", "1")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || f.resourceRevokeCalls != 0 {
		t.Fatalf("status=%d remote calls=%d", response.Code, f.resourceRevokeCalls)
	}
	value, owner, err := a.store.acquire(t.Context(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	defer a.store.release(t.Context(), cookie.Value, owner)
	if value.Organization != "org-one" || value.Revision != "1" {
		t.Fatal("non-Cookie request adopted changed organization")
	}
}
