package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
)

func TestBearerToken(t *testing.T) {
	tests := []struct {
		// name 表示测试用例名称。
		name string

		// header 表示待解析的 Authorization Header。
		header string

		// want 表示期望的 Bearer Token。
		want string
	}{
		{name: "bearer", header: "Bearer token", want: "token"},
		{name: "case insensitive", header: "bearer token", want: "token"},
		{name: "missing scheme", header: "token"},
		{name: "wrong scheme", header: "Basic token"},
		{name: "missing token", header: "Bearer"},
		{name: "extra value", header: "Bearer token extra"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := bearerToken(test.header)
			if test.want == "" {
				if !errors.Is(err, auth.ErrInvalidCredential) {
					t.Fatalf("bearerToken error = %v, want ErrInvalidCredential", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("bearerToken: %v", err)
			}
			if got != test.want {
				t.Fatalf("bearerToken = %q, want %q", got, test.want)
			}
		})
	}
}

func TestBearerLoginStatusMiddlewareRejectsInvalidModes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		// name 表示测试用例名称。
		name string

		// cookieName 表示 Bearer 路由拒绝的 Cookie 名称。
		cookieName string

		// cookie 表示请求 Cookie Header。
		cookie string

		// authorization 表示请求 Authorization Header。
		authorization []string

		// wantState 表示期望的认证状态。
		wantState auth.State

		// wantErr 表示期望的认证错误分类。
		wantErr error
	}{
		{name: "missing bearer", cookieName: "__Host-session", wantState: auth.StateNil},
		{name: "configured browser cookie", cookieName: "__Host-session", cookie: "__Host-session=sid", wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential},
		{name: "duplicate authorization", authorization: []string{"Bearer one", "Bearer two"}, wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential},
		{name: "empty authorization", authorization: []string{""}, wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential},
		{name: "wrong scheme", authorization: []string{"Basic value"}, wantState: auth.StateFailed, wantErr: auth.ErrInvalidCredential},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, err := NewBearerLoginStatusMiddleware(test.cookieName)
			if err != nil {
				t.Fatalf("NewBearerLoginStatusMiddleware: %v", err)
			}
			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx.Request = httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
			if test.cookie != "" {
				ctx.Request.Header.Set("Cookie", test.cookie)
			}
			for _, value := range test.authorization {
				ctx.Request.Header.Add("Authorization", value)
			}
			handler(ctx)

			value, _ := ctx.Get(constants.CtxKeyLoginStatus)
			status := value.(*auth.LoginStatus)
			if status.AuthMode != auth.AuthModeBearer || status.State != test.wantState {
				t.Fatalf("LoginStatus = mode %q state %d", status.AuthMode, status.State)
			}
			if test.wantErr != nil && !errors.Is(status.Err, test.wantErr) {
				t.Fatalf("LoginStatus error = %v, want %v", status.Err, test.wantErr)
			}
		})
	}
}

func TestAuthMiddleWareUsesUniformStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		// name 表示测试用例名称。
		name string

		// status 表示上游发布的登录状态。
		status *auth.LoginStatus

		// wantStatus 表示期望的 HTTP 状态码。
		wantStatus int
	}{
		{name: "missing status", wantStatus: http.StatusUnauthorized},
		{name: "invalid credential", status: &auth.LoginStatus{State: auth.StateFailed, Err: auth.ErrInvalidCredential}, wantStatus: http.StatusUnauthorized},
		{name: "backend unavailable", status: &auth.LoginStatus{State: auth.StateFailed, Err: auth.ErrAuthBackendUnavailable}, wantStatus: http.StatusServiceUnavailable},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			if test.status != nil {
				ctx.Set(constants.CtxKeyLoginStatus, test.status)
			}
			AuthMiddleWare(ctx)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
		})
	}
}
