package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/JUXON-AI/jxpkg/apis/runtime/middleware"
	"github.com/gin-gonic/gin"
)

type orderedSessionResolver struct {
	// order 记录中间件执行顺序。
	order *[]string

	// principal 保存测试解析器返回的会话主体。
	principal *auth.SessionPrincipal

	// err 保存测试解析器返回的错误。
	err error
}

func (resolver *orderedSessionResolver) Resolve(_ context.Context, _ auth.SessionResolveRequest) (*auth.SessionPrincipal, error) {
	*resolver.order = append(*resolver.order, "resolve")
	return resolver.principal, resolver.err
}

func TestRouterBrowserSessionChainOrderAndFailures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Unix(2_000_000, 0)
	hash := sha256.Sum256([]byte("csrf-token"))
	validPrincipal := func() *auth.SessionPrincipal {
		return &auth.SessionPrincipal{
			Claims: auth.UserClaims{
				UserID:          1,
				UIN:             2,
				CompanyID:       3,
				MembershipEpoch: 4,
			},
			Host:              "app.example.com",
			ClientID:          "browser-client",
			SessionVersion:    1,
			AuthenticatedAt:   now.Add(-time.Hour).Unix(),
			IdleExpiresAt:     now.Add(time.Hour).Unix(),
			AbsoluteExpiresAt: now.Add(2 * time.Hour).Unix(),
			CSRFTokenHash:     hash[:],
		}
	}

	tests := []struct {
		// name 表示测试用例名称。
		name string

		// method 表示请求 Method。
		method string

		// cookie 表示请求 Cookie Header。
		cookie string

		// origin 表示请求 Origin Header。
		origin string

		// csrf 表示请求 CSRF Header。
		csrf string

		// resolverErr 表示会话解析器返回的错误。
		resolverErr error

		// injectorErr 表示业务身份注入器返回的错误。
		injectorErr error

		// wantStatus 表示期望的 HTTP 状态码。
		wantStatus int

		// wantOrder 表示期望的中间件执行顺序。
		wantOrder []string

		// browserMethod 表示待测试的浏览器路由注册方法。
		browserMethod func(*Router, string, ...interface{})
	}{
		{name: "post fixed order", method: http.MethodPost, cookie: "__Host-app_session=sid", origin: "http://app.example.com", csrf: "csrf-token", wantStatus: http.StatusNoContent, wantOrder: []string{"resolve", "inject", "handler"}, browserMethod: (*Router).PRequireBrowserSession},
		{name: "get skips csrf", method: http.MethodGet, cookie: "__Host-app_session=sid", wantStatus: http.StatusNoContent, wantOrder: []string{"resolve", "inject", "handler"}, browserMethod: (*Router).GRequireBrowserSession},
		{name: "resolver precedes injector", method: http.MethodPost, cookie: "__Host-app_session=sid", origin: "http://app.example.com", csrf: "csrf-token", resolverErr: context.DeadlineExceeded, wantStatus: http.StatusServiceUnavailable, wantOrder: []string{"resolve"}, browserMethod: (*Router).PRequireBrowserSession},
		{name: "injector precedes auth requirement", method: http.MethodPost, cookie: "__Host-app_session=sid", origin: "http://app.example.com", csrf: "csrf-token", injectorErr: auth.ErrAuthBackendUnavailable, wantStatus: http.StatusServiceUnavailable, wantOrder: []string{"resolve", "inject"}, browserMethod: (*Router).PRequireBrowserSession},
		{name: "csrf precedes handler", method: http.MethodPost, cookie: "__Host-app_session=sid", origin: "http://app.example.com", csrf: "wrong", wantStatus: http.StatusUnauthorized, wantOrder: []string{"resolve", "inject"}, browserMethod: (*Router).PRequireBrowserSession},
		{name: "missing cookie precedes injector", method: http.MethodPost, origin: "http://app.example.com", csrf: "csrf-token", wantStatus: http.StatusUnauthorized, wantOrder: []string{}, browserMethod: (*Router).PRequireBrowserSession},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			order := make([]string, 0, 3)
			resolver := &orderedSessionResolver{order: &order, principal: validPrincipal(), err: test.resolverErr}
			router := NewRouter("/v1/", WithBrowserSession(middleware.BrowserSessionOptions{
				Service:      "service",
				CookieName:   "__Host-app_session",
				AllowedHosts: map[string]struct{}{"app.example.com": {}},
				Resolver:     resolver,
				Clock:        func() time.Time { return now },
			}))
			router.AuthInject(func(_ *gin.Context, _ *auth.LoginStatus) error {
				order = append(order, "inject")
				return test.injectorErr
			})
			test.browserMethod(router, "resource", gin.HandlerFunc(func(ctx *gin.Context) {
				order = append(order, "handler")
				ctx.Status(http.StatusNoContent)
			}))

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, "http://app.example.com/v1/resource", nil)
			if test.cookie != "" {
				request.Header.Set("Cookie", test.cookie)
			}
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.csrf != "" {
				request.Header.Set(middleware.DefaultCSRFHeader, test.csrf)
			}
			router.GinEngine().ServeHTTP(recorder, request)

			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if !reflect.DeepEqual(order, test.wantOrder) {
				t.Fatalf("order = %v, want %v", order, test.wantOrder)
			}
		})
	}
}

func TestRouterPublicRouteStaysAnonymous(t *testing.T) {
	gin.SetMode(gin.TestMode)
	resolverCalls := 0
	injectorCalls := 0
	resolver := sessionResolverFunc(func(_ context.Context, _ auth.SessionResolveRequest) (*auth.SessionPrincipal, error) {
		resolverCalls++
		return nil, errors.New("must not resolve")
	})
	router := NewRouter("/v1/", WithBrowserSession(middleware.BrowserSessionOptions{
		Service:      "service",
		CookieName:   "__Host-app_session",
		AllowedHosts: map[string]struct{}{"app.example.com": {}},
		Resolver:     resolver,
	}))
	router.AuthInject(func(_ *gin.Context, _ *auth.LoginStatus) error {
		injectorCalls++
		return nil
	})
	router.Post("public", gin.HandlerFunc(func(ctx *gin.Context) {
		if _, exists := ctx.Get(constants.CtxKeyLoginStatus); exists {
			t.Fatal("public route unexpectedly received LoginStatus")
		}
		ctx.Status(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "http://unknown.example.com/v1/public", nil)
	request.Header.Set("Authorization", "not bearer")
	request.Header.Set("Cookie", "__Host-app_session=invalid")
	router.GinEngine().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusNoContent, recorder.Body.String())
	}
	if resolverCalls != 0 || injectorCalls != 0 {
		t.Fatalf("public route called resolver/injector: %d/%d", resolverCalls, injectorCalls)
	}
}

func TestRouterBearerAndLegacyRoutesRejectConfiguredSessionCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	registrations := []struct {
		// name 表示测试用例名称。
		name string

		// register 表示待测试的路由注册方法。
		register func(*Router, string, ...interface{})
	}{
		{name: "explicit bearer", register: (*Router).GRequireBearer},
		{name: "legacy login", register: (*Router).GRequireLogin},
	}

	for _, registration := range registrations {
		t.Run(registration.name, func(t *testing.T) {
			router := NewRouter("/v1/", WithBrowserSession(middleware.BrowserSessionOptions{
				Service:      "service",
				CookieName:   "__Host-app_session",
				AllowedHosts: map[string]struct{}{"app.example.com": {}},
				Resolver: sessionResolverFunc(func(_ context.Context, _ auth.SessionResolveRequest) (*auth.SessionPrincipal, error) {
					t.Fatal("Bearer route called browser resolver")
					return nil, nil
				}),
			}))
			injectorCalled := false
			router.AuthInject(func(_ *gin.Context, _ *auth.LoginStatus) error {
				injectorCalled = true
				return nil
			})
			registration.register(router, "protected", gin.HandlerFunc(func(ctx *gin.Context) {
				t.Fatal("protected handler was called")
			}))

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "http://app.example.com/v1/protected", nil)
			request.Header.Set("Cookie", "__Host-app_session=sid")
			request.Header.Set("Authorization", "Bearer token")
			router.GinEngine().ServeHTTP(recorder, request)

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
			}
			if injectorCalled {
				t.Fatal("injector was called after mixed credentials")
			}
		})
	}
}

func TestRouterBrowserRouteWithoutConfigurationReturnsUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := NewRouter("/v1/")
	router.GRequireBrowserSession("protected", gin.HandlerFunc(func(ctx *gin.Context) {
		t.Fatal("protected handler was called")
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://app.example.com/v1/protected", nil)
	router.GinEngine().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
}

type sessionResolverFunc func(context.Context, auth.SessionResolveRequest) (*auth.SessionPrincipal, error)

func (resolver sessionResolverFunc) Resolve(ctx context.Context, request auth.SessionResolveRequest) (*auth.SessionPrincipal, error) {
	return resolver(ctx, request)
}

func TestRouterWithCORSWiresConfiguredOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	corsMiddleware, err := middleware.NewCORS(middleware.CORSOptions{
		AllowedOrigins: []string{"https://ui.example.com"},
	})
	if err != nil {
		t.Fatalf("NewCORS() error = %v", err)
	}
	router := NewRouter("/v1/", WithCORS(corsMiddleware))
	router.G("resource", gin.HandlerFunc(func(ctx *gin.Context) {
		ctx.Status(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1/resource", nil)
	request.Header.Set("Origin", "https://ui.example.com")
	router.GinEngine().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://ui.example.com" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
}

func TestWithBrowserSecurityFailsClosedWhenMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	called := false
	router := NewRouter("/v1/", WithBrowserSecurity(nil))
	router.PRequireBrowserSession("resource", func(ctx *gin.Context) {
		called = true
		ctx.Status(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "https://app.example.com/v1/resource", nil)
	router.GinEngine().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if called {
		t.Fatal("protected handler was called without browser security")
	}
}

func TestRouterWithCORSPreservesCustomMiddlewareOrder(t *testing.T) {
	gin.SetMode(gin.TestMode)
	order := make([]string, 0, 8)
	strictCORS, err := middleware.NewCORS(middleware.CORSOptions{
		AllowedOrigins: []string{"https://ui.example.com"},
	})
	if err != nil {
		t.Fatalf("NewCORS() error = %v", err)
	}
	corsMiddleware := func(ctx *gin.Context) {
		order = append(order, "cors before")
		strictCORS(ctx)
		order = append(order, "cors after")
	}
	orderedMiddleware := func(name string) gin.HandlerFunc {
		return func(ctx *gin.Context) {
			order = append(order, name+" before")
			ctx.Next()
			order = append(order, name+" after")
		}
	}
	router := NewRouter("/v1/",
		WithCORS(corsMiddleware),
		WithMiddleware(orderedMiddleware("first")),
		WithMiddleware(orderedMiddleware("second")),
	)
	router.G("resource", gin.HandlerFunc(func(ctx *gin.Context) {
		order = append(order, "handler")
		ctx.Status(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1/resource", nil)
	request.Header.Set("Origin", "https://ui.example.com")
	router.GinEngine().ServeHTTP(recorder, request)

	wantOrder := []string{
		"cors before",
		"first before",
		"second before",
		"handler",
		"second after",
		"first after",
		"cors after",
	}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("order = %v, want %v", order, wantOrder)
	}
}

func TestRouterCORSAndCSRFShareAuthoritativeExternalOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Unix(2_000_000, 0)
	hash := sha256.Sum256([]byte("csrf-token"))
	principal := &auth.SessionPrincipal{
		Claims: auth.UserClaims{
			UserID:          1,
			UIN:             2,
			CompanyID:       3,
			MembershipEpoch: 4,
		},
		Host:              "app.example.com",
		ClientID:          "browser-client",
		SessionVersion:    1,
		AuthenticatedAt:   now.Add(-time.Hour).Unix(),
		IdleExpiresAt:     now.Add(time.Hour).Unix(),
		AbsoluteExpiresAt: now.Add(2 * time.Hour).Unix(),
		CSRFTokenHash:     hash[:],
	}

	tests := []struct {
		// name 表示测试用例名称。
		name string

		// csrfExternalOrigin 表示浏览器会话 CSRF 使用的外部 Origin。
		csrfExternalOrigin string

		// wantStatus 表示期望的响应状态码。
		wantStatus int

		// wantHandlerCalls 表示期望的业务处理器调用次数。
		wantHandlerCalls int
	}{
		{name: "matching configuration", csrfExternalOrigin: "https://app.example.com", wantStatus: http.StatusNoContent, wantHandlerCalls: 1},
		{name: "mismatched configuration", csrfExternalOrigin: "https://other.example.com", wantStatus: http.StatusUnauthorized},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const corsExternalOrigin = "https://app.example.com"
			corsMiddleware, err := middleware.NewCORS(middleware.CORSOptions{ExternalOrigin: corsExternalOrigin})
			if err != nil {
				t.Fatalf("NewCORS() error = %v", err)
			}
			resolver := sessionResolverFunc(func(_ context.Context, _ auth.SessionResolveRequest) (*auth.SessionPrincipal, error) {
				copy := *principal
				copy.CSRFTokenHash = append([]byte(nil), principal.CSRFTokenHash...)
				return &copy, nil
			})
			router := NewRouter("/v1/",
				WithCORS(corsMiddleware),
				WithBrowserSession(middleware.BrowserSessionOptions{
					Service:    "service",
					CookieName: "__Host-app_session",
					AllowedHosts: map[string]struct{}{
						"app.example.com":   {},
						"other.example.com": {},
					},
					ExternalOrigin: test.csrfExternalOrigin,
					Resolver:       resolver,
					Clock:          func() time.Time { return now },
				}),
			)
			router.AuthInject(func(_ *gin.Context, _ *auth.LoginStatus) error { return nil })
			handlerCalls := 0
			router.PRequireBrowserSession("resource", gin.HandlerFunc(func(ctx *gin.Context) {
				handlerCalls++
				ctx.Status(http.StatusNoContent)
			}))

			request := httptest.NewRequest(http.MethodPost, "http://app.example.com/v1/resource", nil)
			request.Header.Set("Origin", corsExternalOrigin)
			request.Header.Set("Cookie", "__Host-app_session=sid")
			request.Header.Set(middleware.DefaultCSRFHeader, "csrf-token")
			request.Header.Set("X-Forwarded-Host", "attacker.example.com")
			request.Header.Set("X-Forwarded-Proto", "http")
			recorder := httptest.NewRecorder()
			router.GinEngine().ServeHTTP(recorder, request)

			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if handlerCalls != test.wantHandlerCalls {
				t.Fatalf("handler calls = %d, want %d", handlerCalls, test.wantHandlerCalls)
			}
			if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != corsExternalOrigin {
				t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, corsExternalOrigin)
			}
		})
	}
}
