package middleware

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
)

func TestBrowserBindingsSelectExactHost(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Unix(2_000_000, 0)
	hash := sha256.Sum256([]byte("csrf-token"))
	bindings := []BrowserSessionBinding{
		{Host: "a.example.com", Service: "service-a", CookieName: "__Host-a", ExternalOrigin: "https://a.example.com"},
		{Host: "b.example.com:8443", Service: "service-b", CookieName: "__Host-b", ExternalOrigin: "https://b.example.com:8443"},
	}
	tests := []struct {
		name, host, cookie, origin, token, service, sid string
		wantCalls, wantStatus                           int
	}{
		{name: "first host", host: bindings[0].Host, cookie: "__Host-a=sid-a", origin: bindings[0].ExternalOrigin, token: "csrf-token", service: "service-a", sid: "sid-a", wantCalls: 1, wantStatus: 204},
		{name: "second host", host: bindings[1].Host, cookie: "__Host-b=sid-b", origin: bindings[1].ExternalOrigin, token: "csrf-token", service: "service-b", sid: "sid-b", wantCalls: 1, wantStatus: 204},
		{name: "both cookies select current host", host: bindings[1].Host, cookie: "__Host-a=sid-a; __Host-b=sid-b", origin: bindings[1].ExternalOrigin, token: "csrf-token", service: "service-b", sid: "sid-b", wantCalls: 1, wantStatus: 204},
		{name: "sibling cookie only", host: bindings[0].Host, cookie: "__Host-b=sid-b", wantStatus: 401},
		{name: "duplicate selected cookie", host: bindings[0].Host, cookie: "__Host-a=sid-a; __Host-a=sid-a", wantStatus: 401},
		{name: "unknown host", host: "other.example.com", cookie: "__Host-a=sid-a", wantStatus: 401},
		{name: "case is exact", host: "A.example.com", cookie: "__Host-a=sid-a", wantStatus: 401},
		{name: "unregistered default port", host: "a.example.com:443", cookie: "__Host-a=sid-a", wantStatus: 401},
		{name: "registered port required", host: "b.example.com", cookie: "__Host-b=sid-b", wantStatus: 401},
		{name: "cross host origin", host: bindings[0].Host, cookie: "__Host-a=sid-a", origin: bindings[1].ExternalOrigin, token: "csrf-token", service: "service-a", sid: "sid-a", wantCalls: 1, wantStatus: 401},
		{name: "missing csrf", host: bindings[1].Host, cookie: "__Host-b=sid-b", origin: bindings[1].ExternalOrigin, service: "service-b", sid: "sid-b", wantCalls: 1, wantStatus: 401},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &fakeSessionResolver{principal: &auth.SessionPrincipal{
				Claims: auth.UserClaims{UserID: 1, UIN: 2, CompanyID: 3, MembershipEpoch: 4}, Host: test.host, ClientID: "client", SessionVersion: 1,
				AuthenticatedAt: now.Add(-time.Minute).Unix(), IdleExpiresAt: now.Add(time.Hour).Unix(), AbsoluteExpiresAt: now.Add(2 * time.Hour).Unix(), CSRFTokenHash: hash[:],
			}}
			options := BrowserSessionOptions{Bindings: append([]BrowserSessionBinding(nil), bindings...), Resolver: resolver, Clock: func() time.Time { return now }, UnsafeMethods: map[string]struct{}{"CUSTOM": {}}}
			handlers, err := NewBrowserSessionHandlers(options)
			if err != nil {
				t.Fatal(err)
			}
			// Mutating caller-owned configuration must not change any installed boundary.
			options.Bindings[0] = BrowserSessionBinding{Host: "other.example.com", Service: "mutated", CookieName: "__Host-b"}
			options.Bindings[1].ExternalOrigin = "https://attacker.example.com"
			delete(options.UnsafeMethods, "CUSTOM")
			engine := gin.New()
			engine.Handle("CUSTOM", "/resource", handlers.Session, RequireAuthenticated, handlers.CSRF, func(ctx *gin.Context) { ctx.Status(204) })
			request := httptest.NewRequest("CUSTOM", "http://"+test.host+"/resource", nil)
			request.Header.Set("Cookie", test.cookie)
			request.Header.Set("Origin", test.origin)
			request.Header.Set(DefaultCSRFHeader, test.token)
			request.Header.Set("X-Forwarded-Host", bindings[0].Host)
			request.Header.Set("X-Forwarded-Proto", "https")
			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus || resolver.calls != test.wantCalls {
				t.Fatalf("status/calls = %d/%d, want %d/%d", recorder.Code, resolver.calls, test.wantStatus, test.wantCalls)
			}
			if test.wantCalls > 0 && (resolver.request.Service != test.service || resolver.request.SessionID != test.sid || resolver.request.Host != test.host) {
				t.Fatalf("wrong binding selected: %+v", resolver.request)
			}
		})
	}
}

func TestBrowserBindingsBearerCookieBoundary(t *testing.T) {
	options := BrowserSessionOptions{Bindings: []BrowserSessionBinding{
		{Host: "a.example.com", Service: "a", CookieName: "__Host-a"},
		{Host: "b.example.com", Service: "b", CookieName: "__Host-b"},
	}, Resolver: &fakeSessionResolver{}}
	handlers, err := NewBrowserSessionHandlers(options)
	if err != nil {
		t.Fatal(err)
	}
	options.Bindings[0].CookieName = "__Host-b"
	for _, test := range []struct {
		name, host, cookie string
		reject             bool
	}{
		{"current cookie", "a.example.com", "__Host-a=sid", true},
		{"empty current cookie", "a.example.com", "__Host-a=", true},
		{"sibling cookie", "a.example.com", "__Host-b=sid", false},
		{"second current cookie", "b.example.com", "__Host-b=sid", true},
		{"second sibling cookie", "b.example.com", "__Host-a=sid", false},
		{"no cookie", "a.example.com", "", false},
		{"unknown host uses bearer", "other.example.com", "", false},
		{"unknown port has no browser cookie", "a.example.com:443", "__Host-a=sid", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx.Request = httptest.NewRequest(http.MethodPost, "http://"+test.host+"/", nil)
			ctx.Request.Header.Set("Cookie", test.cookie)
			handlers.Bearer(ctx)
			status := ctx.MustGet(constants.CtxKeyLoginStatus).(*auth.LoginStatus)
			if errors.Is(status.Err, auth.ErrInvalidCredential) != test.reject {
				t.Fatalf("rejected = %v, want %v", status.Err, test.reject)
			}
			RequireAuthenticated(ctx)
			if !ctx.IsAborted() {
				t.Fatal("missing Bearer token bypassed authentication")
			}

			ctx, _ = gin.CreateTestContext(httptest.NewRecorder())
			ctx.Request = httptest.NewRequest(http.MethodPost, "http://"+test.host+"/", nil)
			ctx.Request.Header.Set("Cookie", test.cookie)
			ctx.Request.Header.Set("Authorization", "Basic not-bearer")
			handlers.Bearer(ctx)
			status = ctx.MustGet(constants.CtxKeyLoginStatus).(*auth.LoginStatus)
			if !errors.Is(status.Err, auth.ErrInvalidCredential) {
				t.Fatal("non-Bearer authorization was not rejected")
			}
		})
	}
}

func TestBrowserBindingsRejectWholeInvalidDirectory(t *testing.T) {
	valid := BrowserSessionBinding{Host: "a.example.com", Service: "a", CookieName: "__Host-a", ExternalOrigin: "https://a.example.com"}
	for _, test := range []struct {
		name     string
		bindings []BrowserSessionBinding
	}{
		{"empty", nil},
		{"duplicate", []BrowserSessionBinding{valid, valid}},
		{"invalid second", []BrowserSessionBinding{valid, {Host: "B.example.com", Service: "b", CookieName: "__Host-b"}}},
		{"cross host origin", []BrowserSessionBinding{{Host: valid.Host, Service: valid.Service, CookieName: valid.CookieName, ExternalOrigin: "https://b.example.com"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			handlers, err := NewBrowserSessionHandlers(BrowserSessionOptions{Bindings: test.bindings, Resolver: &fakeSessionResolver{}})
			if !errors.Is(err, auth.ErrAuthBackendUnavailable) || handlers.Session != nil || handlers.CSRF != nil || handlers.Bearer != nil {
				t.Fatalf("partial directory accepted: %v", err)
			}
		})
	}
}

func TestTypedNilLoginStatusFailsClosed(t *testing.T) {
	handlers, err := NewBrowserSessionHandlers(BrowserSessionOptions{Bindings: []BrowserSessionBinding{{Host: "a.example.com", Service: "a", CookieName: "__Host-a"}}, Resolver: &fakeSessionResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	for name, handler := range map[string]gin.HandlerFunc{"require authenticated": RequireAuthenticated, "csrf": handlers.CSRF} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPost, "http://a.example.com/", nil)
			ctx.Set(constants.CtxKeyLoginStatus, (*auth.LoginStatus)(nil))
			handler(ctx)
			if recorder.Code != http.StatusUnauthorized || !ctx.IsAborted() {
				t.Fatalf("nil principal did not fail closed: %d", recorder.Code)
			}
		})
	}
}
