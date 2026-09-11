package middleware

import (
	"context"
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

type fakeSessionResolver struct {
	// principal 保存测试解析器返回的会话主体。
	principal *auth.SessionPrincipal

	// err 保存测试解析器返回的错误。
	err error

	// request 保存测试解析器收到的请求。
	request auth.SessionResolveRequest

	// calls 记录测试解析器调用次数。
	calls int
}

func newTestBrowserSessionMiddleware(options BrowserSessionOptions) (gin.HandlerFunc, error) {
	handlers, err := NewBrowserSessionHandlers(options)
	return handlers.Session, err
}

func newTestCSRFMiddleware(options BrowserSessionOptions) (gin.HandlerFunc, error) {
	options.Resolver = &fakeSessionResolver{}
	handlers, err := NewBrowserSessionHandlers(options)
	return handlers.CSRF, err
}

func (resolver *fakeSessionResolver) Resolve(_ context.Context, request auth.SessionResolveRequest) (*auth.SessionPrincipal, error) {
	resolver.calls++
	resolver.request = request
	return resolver.principal, resolver.err
}

func TestBrowserSessionMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Unix(2_000_000, 0)
	csrfHash := sha256.Sum256([]byte("csrf-token"))
	validPrincipal := func() *auth.SessionPrincipal {
		return &auth.SessionPrincipal{
			Claims: auth.UserClaims{
				UserID:          11,
				UIN:             22,
				CompanyID:       33,
				MembershipEpoch: 44,
			},
			Host:              "app.example.com",
			ClientID:          "browser-client",
			SessionVersion:    5,
			AuthenticatedAt:   now.Add(-time.Hour).Unix(),
			IdleExpiresAt:     now.Add(time.Hour).Unix(),
			AbsoluteExpiresAt: now.Add(2 * time.Hour).Unix(),
			CSRFTokenHash:     append([]byte(nil), csrfHash[:]...),
		}
	}

	tests := []struct {
		// name 表示测试用例名称。
		name string

		// host 表示请求 Host。
		host string

		// cookies 表示请求 Cookie Header。
		cookies []string

		// authorization 表示请求 Authorization Header。
		authorization []string

		// principal 创建解析器返回的会话主体。
		principal func() *auth.SessionPrincipal

		// resolverErr 表示解析器返回的错误。
		resolverErr error

		// wantState 表示期望的认证状态。
		wantState auth.State

		// wantErr 表示期望的认证错误分类。
		wantErr error

		// wantCalls 表示期望的解析器调用次数。
		wantCalls int
	}{
		{name: "valid", host: "app.example.com", cookies: []string{"__Host-app_session=sid"}, principal: validPrincipal, wantState: auth.StateSucc, wantCalls: 1},
		{name: "missing cookie", host: "app.example.com", principal: validPrincipal, wantState: auth.StateNil},
		{name: "empty cookie", host: "app.example.com", cookies: []string{"__Host-app_session="}, principal: validPrincipal, wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential},
		{name: "duplicate cookie", host: "app.example.com", cookies: []string{"__Host-app_session=one; __Host-app_session=two"}, principal: validPrincipal, wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential},
		{name: "authorization header", host: "app.example.com", cookies: []string{"__Host-app_session=sid"}, authorization: []string{"Bearer token"}, principal: validPrincipal, wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential},
		{name: "empty authorization header", host: "app.example.com", cookies: []string{"__Host-app_session=sid"}, authorization: []string{""}, principal: validPrincipal, wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential},
		{name: "unknown host", host: "other.example.com", cookies: []string{"__Host-app_session=sid"}, principal: validPrincipal, wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential},
		{name: "unexpected port", host: "app.example.com:443", cookies: []string{"__Host-app_session=sid"}, principal: validPrincipal, wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential},
		{name: "trailing dot", host: "app.example.com.", cookies: []string{"__Host-app_session=sid"}, principal: validPrincipal, wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential},
		{name: "uppercase host", host: "APP.example.com", cookies: []string{"__Host-app_session=sid"}, principal: validPrincipal, wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential},
		{name: "invalid session", host: "app.example.com", cookies: []string{"__Host-app_session=sid"}, principal: validPrincipal, resolverErr: auth.ErrInvalidCredential, wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential, wantCalls: 1},
		{name: "resolver outage", host: "app.example.com", cookies: []string{"__Host-app_session=sid"}, principal: validPrincipal, resolverErr: context.DeadlineExceeded, wantState: auth.StateFailed, wantErr: auth.ErrAuthBackendUnavailable, wantCalls: 1},
		{name: "nil principal", host: "app.example.com", cookies: []string{"__Host-app_session=sid"}, wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential, wantCalls: 1},
		{name: "wrong principal host", host: "app.example.com", cookies: []string{"__Host-app_session=sid"}, principal: func() *auth.SessionPrincipal { p := validPrincipal(); p.Host = "other.example.com"; return p }, wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential, wantCalls: 1},
		{name: "idle expired", host: "app.example.com", cookies: []string{"__Host-app_session=sid"}, principal: func() *auth.SessionPrincipal { p := validPrincipal(); p.IdleExpiresAt = now.Unix(); return p }, wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential, wantCalls: 1},
		{name: "absolute expired", host: "app.example.com", cookies: []string{"__Host-app_session=sid"}, principal: func() *auth.SessionPrincipal {
			p := validPrincipal()
			p.AbsoluteExpiresAt = now.Unix()
			p.IdleExpiresAt = now.Add(-time.Second).Unix()
			return p
		}, wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential, wantCalls: 1},
		{name: "zero session version", host: "app.example.com", cookies: []string{"__Host-app_session=sid"}, principal: func() *auth.SessionPrincipal { p := validPrincipal(); p.SessionVersion = 0; return p }, wantState: auth.StateFailed, wantErr: auth.ErrAuthBackendUnavailable, wantCalls: 1},
		{name: "future authentication", host: "app.example.com", cookies: []string{"__Host-app_session=sid"}, principal: func() *auth.SessionPrincipal {
			p := validPrincipal()
			p.AuthenticatedAt = now.Add(time.Second).Unix()
			return p
		}, wantState: auth.StateFailed, wantErr: auth.ErrAuthBackendUnavailable, wantCalls: 1},
		{name: "idle beyond absolute", host: "app.example.com", cookies: []string{"__Host-app_session=sid"}, principal: func() *auth.SessionPrincipal {
			p := validPrincipal()
			p.IdleExpiresAt = p.AbsoluteExpiresAt + 1
			return p
		}, wantState: auth.StateFailed, wantErr: auth.ErrAuthBackendUnavailable, wantCalls: 1},
		{name: "invalid csrf hash", host: "app.example.com", cookies: []string{"__Host-app_session=sid"}, principal: func() *auth.SessionPrincipal { p := validPrincipal(); p.CSRFTokenHash = []byte("short"); return p }, wantState: auth.StateFailed, wantErr: auth.ErrAuthBackendUnavailable, wantCalls: 1},
		{name: "invalid claims", host: "app.example.com", cookies: []string{"__Host-app_session=sid"}, principal: func() *auth.SessionPrincipal { p := validPrincipal(); p.Claims.UIN = 0; return p }, wantState: auth.StateFailed, wantErr: auth.ErrInvalidPrincipal, wantCalls: 1},
		{name: "zero membership epoch", host: "app.example.com", cookies: []string{"__Host-app_session=sid"}, principal: func() *auth.SessionPrincipal { p := validPrincipal(); p.Claims.MembershipEpoch = 0; return p }, wantState: auth.StateFailed, wantErr: auth.ErrInvalidPrincipal, wantCalls: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &fakeSessionResolver{err: test.resolverErr}
			if test.principal != nil {
				resolver.principal = test.principal()
			}
			handler, err := newTestBrowserSessionMiddleware(BrowserSessionOptions{
				Bindings: []BrowserSessionBinding{{Host: "app.example.com", Service: "juxonone", CookieName: "__Host-app_session"}},
				Resolver: resolver,
				Clock:    func() time.Time { return now },
			})
			if err != nil {
				t.Fatalf("NewBrowserSessionMiddleware: %v", err)
			}

			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodGet, "http://"+test.host+"/resource", nil)
			for _, cookie := range test.cookies {
				ctx.Request.Header.Add("Cookie", cookie)
			}
			for _, value := range test.authorization {
				ctx.Request.Header.Add("Authorization", value)
			}
			handler(ctx)

			value, ok := ctx.Get(constants.CtxKeyLoginStatus)
			if !ok {
				t.Fatal("LoginStatus was not published")
			}
			status := value.(*auth.LoginStatus)
			if status.AuthMode != auth.AuthModeBrowserSession || status.State != test.wantState {
				t.Fatalf("LoginStatus = mode %q state %d, want browser state %d", status.AuthMode, status.State, test.wantState)
			}
			if test.wantErr != nil && !errors.Is(status.Err, test.wantErr) {
				t.Fatalf("LoginStatus error = %v, want %v", status.Err, test.wantErr)
			}
			if resolver.calls != test.wantCalls {
				t.Fatalf("resolver calls = %d, want %d", resolver.calls, test.wantCalls)
			}
			if test.wantState == auth.StateSucc {
				if status.Claim == &resolver.principal.Claims {
					t.Fatal("middleware retained a resolver-owned Claims pointer")
				}
				if resolver.request != (auth.SessionResolveRequest{Host: "app.example.com", Service: "juxonone", SessionID: "sid"}) {
					t.Fatalf("resolve request = %#v", resolver.request)
				}
				resolver.principal.CSRFTokenHash[0] ^= 0xff
				if !status.MatchesBrowserCSRF("csrf-token") {
					t.Fatal("LoginStatus metadata changed after resolver principal mutation")
				}
			}
		})
	}
}

func TestBrowserSessionOptionsValidation(t *testing.T) {
	resolver := &fakeSessionResolver{}
	base := BrowserSessionOptions{
		Bindings: []BrowserSessionBinding{{Host: "app.example.com", Service: "service", CookieName: "__Host-session"}},
		Resolver: resolver,
	}

	tests := []struct {
		// name 表示测试用例名称。
		name string

		// mutate 构造无效配置。
		mutate func(*BrowserSessionOptions)
	}{
		{name: "empty service", mutate: func(options *BrowserSessionOptions) { options.Bindings[0].Service = "" }},
		{name: "spaced service", mutate: func(options *BrowserSessionOptions) { options.Bindings[0].Service = " service " }},
		{name: "cookie without host prefix", mutate: func(options *BrowserSessionOptions) { options.Bindings[0].CookieName = "session" }},
		{name: "invalid cookie name", mutate: func(options *BrowserSessionOptions) { options.Bindings[0].CookieName = "__Host-bad name" }},
		{name: "empty allowed hosts", mutate: func(options *BrowserSessionOptions) { options.Bindings = nil }},
		{name: "noncanonical allowed host", mutate: func(options *BrowserSessionOptions) {
			options.Bindings[0].Host = "App.example.com"
		}},
		{name: "noncanonical external origin", mutate: func(options *BrowserSessionOptions) {
			options.Bindings[0].ExternalOrigin = "https://App.example.com"
		}},
		{name: "external origin host mismatch", mutate: func(options *BrowserSessionOptions) {
			options.Bindings[0].ExternalOrigin = "https://other.example.com"
		}},
		{name: "nil resolver", mutate: func(options *BrowserSessionOptions) { options.Resolver = nil }},
		{name: "invalid csrf header", mutate: func(options *BrowserSessionOptions) { options.CSRFHeader = "bad header" }},
		{name: "lowercase unsafe method", mutate: func(options *BrowserSessionOptions) { options.UnsafeMethods = map[string]struct{}{"post": {}} }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := base
			options.Bindings = append([]BrowserSessionBinding(nil), base.Bindings...)
			test.mutate(&options)
			if _, err := newTestBrowserSessionMiddleware(options); !errors.Is(err, auth.ErrAuthBackendUnavailable) {
				t.Fatalf("error = %v, want ErrAuthBackendUnavailable", err)
			}
		})
	}
}
