package middleware

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCORSAllowsRequestsWithoutOriginAndExactSameOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handlerCalls := 0
	engine := corsTestEngine(t, CORSOptions{}, func(ctx *gin.Context) {
		handlerCalls++
		ctx.String(http.StatusOK, "ok")
	})

	tests := []struct {
		// name 表示测试用例名称。
		name string

		// target 表示请求目标 URL。
		target string

		// origin 表示请求 Origin Header。
		origin string

		// wantAllowOrigin 表示期望返回的 Allow-Origin。
		wantAllowOrigin string
	}{
		{name: "no origin", target: "http://app.example.com/resource"},
		{name: "http same origin", target: "http://app.example.com/resource", origin: "http://app.example.com", wantAllowOrigin: "http://app.example.com"},
		{name: "https same origin", target: "https://app.example.com/resource", origin: "https://app.example.com", wantAllowOrigin: "https://app.example.com"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK || recorder.Body.String() != "ok" {
				t.Fatalf("response = %d %q, want %d %q", recorder.Code, recorder.Body.String(), http.StatusOK, "ok")
			}
			if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != test.wantAllowOrigin {
				t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, test.wantAllowOrigin)
			}
			if test.origin == "" && recorder.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatal("request without Origin received credentialed CORS headers")
			}
		})
	}
	if handlerCalls != len(tests) {
		t.Fatalf("handler calls = %d, want %d", handlerCalls, len(tests))
	}
}

func TestCORSRejectsNonCanonicalAndUnconfiguredOriginsBeforeHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handlerCalls := 0
	engine := corsTestEngine(t, CORSOptions{AllowedOrigins: []string{"https://ui.example.com:8443"}}, func(ctx *gin.Context) {
		handlerCalls++
		ctx.Status(http.StatusNoContent)
	})

	origins := []string{
		"null",
		"https://user@api.example.com",
		" https://api.example.com",
		`https://api.example.com\attacker.example`,
		"https://API.example.com",
		"https://api.example.com:443",
		"https://api.example.com.",
		"https://api.example.com.attacker.example",
		"https://unconfigured.example.com",
		"https://ui.example.com",
		"https://api.example.com/path",
		"://api.example.com",
	}
	for _, origin := range origins {
		t.Run(origin, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
			request.Header.Set("Origin", origin)
			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
			}
		})
	}

	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	request.Header.Add("Origin", "https://api.example.com")
	request.Header.Add("Origin", "https://ui.example.com:8443")
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("multiple Origin status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if handlerCalls != 0 {
		t.Fatalf("handler calls = %d, want 0", handlerCalls)
	}
}

func TestCORSUsesAuthoritativeExternalOriginAndIgnoresForwardedHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("external origin", func(t *testing.T) {
		engine := corsTestEngine(t, CORSOptions{ExternalOrigin: "https://app.example.com"}, func(ctx *gin.Context) {
			ctx.Status(http.StatusNoContent)
		})
		request := httptest.NewRequest(http.MethodGet, "http://internal.service/resource", nil)
		request.Header.Set("Origin", "https://app.example.com")
		recorder := httptest.NewRecorder()
		engine.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
		}
		if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
			t.Fatalf("Access-Control-Allow-Origin = %q", got)
		}
	})

	t.Run("forwarded headers are not authoritative", func(t *testing.T) {
		handlerCalled := false
		engine := corsTestEngine(t, CORSOptions{}, func(ctx *gin.Context) {
			handlerCalled = true
		})
		request := httptest.NewRequest(http.MethodGet, "http://internal.service/resource", nil)
		request.Header.Set("Origin", "https://app.example.com")
		request.Header.Set("X-Forwarded-Host", "app.example.com")
		request.Header.Set("X-Forwarded-Proto", "https")
		recorder := httptest.NewRecorder()
		engine.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
		}
		if handlerCalled {
			t.Fatal("handler was called for forwarded-header origin")
		}
	})
}

func TestCORSRestoresCredentialedHeadersAtEveryResponseCommitPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		// name 表示提交响应的方式。
		name string

		// handler 表示测试使用的响应处理器。
		handler gin.HandlerFunc

		// wantStatus 表示期望的状态码。
		wantStatus int

		// wantBody 表示期望的响应体。
		wantBody string

		// wantVary 表示下游设置且应保留的 Vary 值。
		wantVary string
	}{
		{
			name: "WriteHeader",
			handler: func(ctx *gin.Context) {
				overwriteCORSHeaders(ctx, "Accept-Language")
				ctx.Writer.WriteHeader(http.StatusCreated)
				ctx.Header("Vary", "Accept-Encoding")
			},
			wantStatus: http.StatusCreated,
			wantVary:   "Accept-Encoding",
		},
		{
			name: "WriteHeaderNow",
			handler: func(ctx *gin.Context) {
				overwriteCORSHeaders(ctx, "Accept-Language")
				ctx.Writer.WriteHeader(http.StatusAccepted)
				ctx.Writer.WriteHeaderNow()
			},
			wantStatus: http.StatusAccepted,
			wantVary:   "Accept-Language",
		},
		{
			name: "Write",
			handler: func(ctx *gin.Context) {
				overwriteCORSHeaders(ctx, "Accept-Encoding")
				ctx.Writer.WriteHeader(http.StatusPartialContent)
				_, _ = ctx.Writer.Write([]byte("bytes"))
			},
			wantStatus: http.StatusPartialContent,
			wantBody:   "bytes",
			wantVary:   "Accept-Encoding",
		},
		{
			name: "WriteString",
			handler: func(ctx *gin.Context) {
				overwriteCORSHeaders(ctx, "Accept-Language")
				ctx.Writer.WriteHeader(http.StatusOK)
				_, _ = ctx.Writer.WriteString("string")
			},
			wantStatus: http.StatusOK,
			wantBody:   "string",
			wantVary:   "Accept-Language",
		},
		{
			name: "Flush streaming",
			handler: func(ctx *gin.Context) {
				overwriteCORSHeaders(ctx, "Accept-Encoding")
				ctx.Writer.WriteHeader(http.StatusOK)
				ctx.Writer.Flush()
				_, _ = ctx.Writer.WriteString("stream")
			},
			wantStatus: http.StatusOK,
			wantBody:   "stream",
			wantVary:   "Accept-Encoding",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine := corsTestEngine(t, CORSOptions{
				AllowedOrigins: []string{"https://ui.example.com"},
				ExposedHeaders: []string{"X-Request-ID"},
			}, test.handler)
			request := httptest.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
			request.Header.Set("Origin", "https://ui.example.com")
			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, request)

			if recorder.Code != test.wantStatus || recorder.Body.String() != test.wantBody {
				t.Fatalf("response = %d %q, want %d %q", recorder.Code, recorder.Body.String(), test.wantStatus, test.wantBody)
			}
			if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://ui.example.com" {
				t.Fatalf("Access-Control-Allow-Origin = %q", got)
			}
			if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
				t.Fatalf("Access-Control-Allow-Credentials = %q", got)
			}
			if got := recorder.Header().Get("Access-Control-Expose-Headers"); got != "X-Request-Id" {
				t.Fatalf("Access-Control-Expose-Headers = %q", got)
			}
			assertVary(t, recorder.Header(), "Origin", test.wantVary)
		})
	}
}

func TestCORSPreflightGrantsOnlyRequestedConfiguredCapabilities(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handlerCalled := false
	engine := corsTestEngine(t, CORSOptions{
		AllowedOrigins: []string{"https://ui.example.com"},
		AllowedMethods: []string{http.MethodGet, http.MethodPost},
		AllowedHeaders: []string{"Content-Type", "X-CSRF-Token"},
	}, func(ctx *gin.Context) {
		handlerCalled = true
	})

	request := httptest.NewRequest(http.MethodOptions, "https://api.example.com/resource", nil)
	request.Header.Set("Origin", "https://ui.example.com")
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	request.Header.Set("Access-Control-Request-Headers", "x-csrf-token, content-type")
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if handlerCalled {
		t.Fatal("handler was called for preflight")
	}
	if got := recorder.Header().Get("Access-Control-Allow-Methods"); got != http.MethodPost {
		t.Fatalf("Access-Control-Allow-Methods = %q, want %q", got, http.MethodPost)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Headers"); got != "X-Csrf-Token, Content-Type" {
		t.Fatalf("Access-Control-Allow-Headers = %q", got)
	}
	if strings.Contains(recorder.Header().Get("Access-Control-Allow-Methods"), http.MethodGet) ||
		strings.Contains(strings.ToLower(recorder.Header().Get("Access-Control-Allow-Headers")), "authorization") {
		t.Fatal("preflight granted an unrequested capability")
	}
	assertVary(t, recorder.Header(), "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers")
}

func TestCORSRejectsInvalidPreflightAndCrossOriginMethod(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		// name 表示测试用例名称。
		name string

		// method 表示实际请求方法。
		method string

		// requestedMethod 表示预检申请的方法。
		requestedMethod []string

		// requestedHeaders 表示预检申请的请求头。
		requestedHeaders string
	}{
		{name: "actual method", method: http.MethodDelete},
		{name: "preflight method", method: http.MethodOptions, requestedMethod: []string{http.MethodDelete}},
		{name: "preflight header", method: http.MethodOptions, requestedMethod: []string{http.MethodPost}, requestedHeaders: "Authorization"},
		{name: "multiple requested methods", method: http.MethodOptions, requestedMethod: []string{http.MethodPost, http.MethodGet}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handlerCalled := false
			engine := corsTestEngine(t, CORSOptions{
				AllowedOrigins: []string{"https://ui.example.com"},
				AllowedMethods: []string{http.MethodPost},
				AllowedHeaders: []string{"Content-Type"},
			}, func(ctx *gin.Context) {
				handlerCalled = true
			})
			request := httptest.NewRequest(test.method, "https://api.example.com/resource", nil)
			request.Header.Set("Origin", "https://ui.example.com")
			for _, method := range test.requestedMethod {
				request.Header.Add("Access-Control-Request-Method", method)
			}
			if test.requestedHeaders != "" {
				request.Header.Set("Access-Control-Request-Headers", test.requestedHeaders)
			}
			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
			}
			if handlerCalled {
				t.Fatal("handler was called for rejected CORS request")
			}
			if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("rejected request received CORS grant headers")
			}
		})
	}
}

func TestNewCORSRejectsInvalidConfiguration(t *testing.T) {
	tests := []CORSOptions{
		{AllowedOrigins: []string{"*"}},
		{AllowedOrigins: []string{"https://*.example.com"}},
		{AllowedOrigins: []string{"https://app.example.com/"}},
		{AllowedOrigins: []string{"HTTPS://app.example.com"}},
		{ExternalOrigin: "https://app.example.com."},
		{AllowedMethods: []string{"post"}},
		{AllowedMethods: []string{"*"}},
		{AllowedHeaders: []string{"*"}},
		{AllowedHeaders: []string{"Bad Header"}},
		{ExposedHeaders: []string{"Bad,Header"}},
	}
	for _, options := range tests {
		if _, err := NewCORS(options); err == nil {
			t.Fatalf("NewCORS(%+v) succeeded, want error", options)
		}
	}
}

func corsTestEngine(t *testing.T, options CORSOptions, handler gin.HandlerFunc) *gin.Engine {
	t.Helper()
	corsMiddleware, err := NewCORS(options)
	if err != nil {
		t.Fatalf("NewCORS() error = %v", err)
	}
	engine := gin.New()
	engine.Use(corsMiddleware)
	engine.Any("/resource", handler)
	return engine
}

func overwriteCORSHeaders(ctx *gin.Context, vary string) {
	ctx.Header("Access-Control-Allow-Origin", "*")
	ctx.Header("Access-Control-Allow-Credentials", "false")
	ctx.Header("Access-Control-Expose-Headers", "X-Secret")
	ctx.Header("Vary", vary)
}

func assertVary(t *testing.T, header http.Header, want ...string) {
	t.Helper()
	got := make([]string, 0)
	for _, line := range header.Values("Vary") {
		for _, value := range strings.Split(line, ",") {
			if value = strings.TrimSpace(value); value != "" {
				got = append(got, strings.ToLower(value))
			}
		}
	}
	wantLower := make([]string, len(want))
	for index, value := range want {
		wantLower[index] = strings.ToLower(value)
	}
	sort.Strings(got)
	sort.Strings(wantLower)
	if !reflect.DeepEqual(got, wantLower) {
		t.Fatalf("Vary = %v, want %v", got, wantLower)
	}
}
