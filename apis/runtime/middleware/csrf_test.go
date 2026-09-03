package middleware

import (
	"crypto/sha256"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
)

func TestCSRFMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	hash := sha256.Sum256([]byte("csrf-token"))
	principal := auth.SessionPrincipal{
		Host:           "app.example.com",
		ClientID:       "browser-client",
		SessionVersion: 1,
		CSRFTokenHash:  hash[:],
	}
	newStatus := func() *auth.LoginStatus {
		return auth.NewBrowserSessionLoginStatus(principal)
	}
	handler, err := NewCSRFMiddleware(BrowserSessionOptions{
		Service:      "service",
		CookieName:   "__Host-session",
		AllowedHosts: map[string]struct{}{"app.example.com": {}},
	})
	if err != nil {
		t.Fatalf("NewCSRFMiddleware: %v", err)
	}

	tests := []struct {
		// name 表示测试用例名称。
		name string

		// method 表示请求 Method。
		method string

		// host 表示请求 Host。
		host string

		// origin 表示请求 Origin Header。
		origin []string

		// tokens 表示请求 CSRF Header。
		tokens []string

		// tls 表示请求是否使用 TLS。
		tls bool

		// mode 表示请求登录状态的认证模式。
		mode auth.AuthMode

		// wantStatus 表示期望的 HTTP 状态码。
		wantStatus int
	}{
		{name: "safe method bypasses csrf", method: http.MethodGet, host: "app.example.com", mode: auth.AuthModeBrowserSession, wantStatus: http.StatusOK},
		{name: "valid http", method: http.MethodPost, host: "app.example.com", origin: []string{"http://app.example.com"}, tokens: []string{"csrf-token"}, mode: auth.AuthModeBrowserSession, wantStatus: http.StatusOK},
		{name: "valid https", method: http.MethodPost, host: "app.example.com", origin: []string{"https://app.example.com"}, tokens: []string{"csrf-token"}, tls: true, mode: auth.AuthModeBrowserSession, wantStatus: http.StatusOK},
		{name: "missing origin", method: http.MethodPost, host: "app.example.com", tokens: []string{"csrf-token"}, mode: auth.AuthModeBrowserSession, wantStatus: http.StatusUnauthorized},
		{name: "null origin", method: http.MethodPost, host: "app.example.com", origin: []string{"null"}, tokens: []string{"csrf-token"}, mode: auth.AuthModeBrowserSession, wantStatus: http.StatusUnauthorized},
		{name: "duplicate origin", method: http.MethodPost, host: "app.example.com", origin: []string{"http://app.example.com", "http://app.example.com"}, tokens: []string{"csrf-token"}, mode: auth.AuthModeBrowserSession, wantStatus: http.StatusUnauthorized},
		{name: "sibling origin", method: http.MethodPost, host: "app.example.com", origin: []string{"http://other.example.com"}, tokens: []string{"csrf-token"}, mode: auth.AuthModeBrowserSession, wantStatus: http.StatusUnauthorized},
		{name: "origin port mismatch", method: http.MethodPost, host: "app.example.com", origin: []string{"http://app.example.com:80"}, tokens: []string{"csrf-token"}, mode: auth.AuthModeBrowserSession, wantStatus: http.StatusUnauthorized},
		{name: "origin scheme mismatch", method: http.MethodPost, host: "app.example.com", origin: []string{"https://app.example.com"}, tokens: []string{"csrf-token"}, mode: auth.AuthModeBrowserSession, wantStatus: http.StatusUnauthorized},
		{name: "origin path", method: http.MethodPost, host: "app.example.com", origin: []string{"http://app.example.com/path"}, tokens: []string{"csrf-token"}, mode: auth.AuthModeBrowserSession, wantStatus: http.StatusUnauthorized},
		{name: "missing token", method: http.MethodPost, host: "app.example.com", origin: []string{"http://app.example.com"}, mode: auth.AuthModeBrowserSession, wantStatus: http.StatusUnauthorized},
		{name: "wrong token", method: http.MethodPost, host: "app.example.com", origin: []string{"http://app.example.com"}, tokens: []string{"wrong"}, mode: auth.AuthModeBrowserSession, wantStatus: http.StatusUnauthorized},
		{name: "duplicate token", method: http.MethodPost, host: "app.example.com", origin: []string{"http://app.example.com"}, tokens: []string{"csrf-token", "csrf-token"}, mode: auth.AuthModeBrowserSession, wantStatus: http.StatusUnauthorized},
		{name: "wrong auth mode", method: http.MethodPost, host: "app.example.com", origin: []string{"http://app.example.com"}, tokens: []string{"csrf-token"}, mode: auth.AuthModeBearer, wantStatus: http.StatusUnauthorized},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(test.method, "http://"+test.host+"/resource", nil)
			if test.tls {
				ctx.Request.TLS = &tls.ConnectionState{}
			}
			for _, value := range test.origin {
				ctx.Request.Header.Add("Origin", value)
			}
			for _, value := range test.tokens {
				ctx.Request.Header.Add(DefaultCSRFHeader, value)
			}
			status := newStatus()
			status.AuthMode = test.mode
			ctx.Set(constants.CtxKeyLoginStatus, status)

			handler(ctx)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if test.wantStatus == http.StatusUnauthorized && !ctx.IsAborted() {
				t.Fatal("CSRF rejection did not abort context")
			}
		})
	}
}
