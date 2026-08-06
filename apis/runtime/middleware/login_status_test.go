package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const testJWTSecret = "0123456789abcdef0123456789abcdef"

func TestLoginStatusAcceptsValidBearerToken(t *testing.T) {
	issuer := "middleware-valid"
	audience := "jxone-web"
	registerTestIssuer(t, issuer, audience)
	token := signTestToken(t, jwt.SigningMethodHS256, auth.UserClaims{
		Uin:       42,
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Issuer:    issuer,
		Audience:  audience,
	})

	status := performProtectedRequest(auth.AuthBearer + token)
	if status != http.StatusNoContent {
		t.Fatalf("expected valid token to pass, got status %d", status)
	}
}

func TestLoginStatusRejectsUnsafeCredentials(t *testing.T) {
	issuer := "middleware-rejected"
	audience := "jxone-web"
	registerTestIssuer(t, issuer, audience)
	now := time.Now()

	tests := []struct {
		name          string
		authorization func(t *testing.T) string
	}{
		{
			name: "unverified api key",
			authorization: func(t *testing.T) string {
				return auth.AuthBearer + auth.AuthAPIKeyPrefix + "anything"
			},
		},
		{
			name: "unsupported authorization scheme",
			authorization: func(t *testing.T) string {
				return "Basic abc"
			},
		},
		{
			name: "wrong audience",
			authorization: func(t *testing.T) string {
				return auth.AuthBearer + signTestToken(t, jwt.SigningMethodHS256, auth.UserClaims{
					Uin: 1, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
					Issuer: issuer, Audience: "another-app",
				})
			},
		},
		{
			name: "wrong signing method",
			authorization: func(t *testing.T) string {
				return auth.AuthBearer + signTestToken(t, jwt.SigningMethodHS512, auth.UserClaims{
					Uin: 1, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
					Issuer: issuer, Audience: audience,
				})
			},
		},
		{
			name: "expired token",
			authorization: func(t *testing.T) string {
				return auth.AuthBearer + signTestToken(t, jwt.SigningMethodHS256, auth.UserClaims{
					Uin: 1, IssuedAt: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(-time.Minute).Unix(),
					Issuer: issuer, Audience: audience,
				})
			},
		},
		{
			name: "missing user",
			authorization: func(t *testing.T) string {
				return auth.AuthBearer + signTestToken(t, jwt.SigningMethodHS256, auth.UserClaims{
					IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
					Issuer: issuer, Audience: audience,
				})
			},
		},
		{
			name: "unknown issuer",
			authorization: func(t *testing.T) string {
				return auth.AuthBearer + signTestToken(t, jwt.SigningMethodHS256, auth.UserClaims{
					Uin: 1, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
					Issuer: "middleware-unknown", Audience: audience,
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := performProtectedRequest(tt.authorization(t))
			if status != http.StatusUnauthorized {
				t.Fatalf("expected credential to be rejected, got status %d", status)
			}
		})
	}
}

func registerTestIssuer(t *testing.T, issuer, audience string) {
	t.Helper()
	if err := auth.RegisterJWTIssuer(auth.JWTIssuerConfig{
		Issuer:   issuer,
		Audience: audience,
		Secret:   testJWTSecret,
	}); err != nil {
		t.Fatalf("register test issuer: %v", err)
	}
}

func signTestToken(t *testing.T, method jwt.SigningMethod, claims auth.UserClaims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(method, &claims).SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("sign test token: %v", err)
	}
	return token
}

func performProtectedRequest(authorization string) int {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(LoginStatus())
	router.GET("/protected", AuthMiddleWare, func(ctx *gin.Context) {
		ctx.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if strings.TrimSpace(authorization) != "" {
		req.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder.Code
}

func TestRequestLogURIRemovesQueryValues(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/assets?token=sensitive", nil)

	if got := requestLogURI(ctx); got != "/assets" {
		t.Fatalf("unexpected logged URI: %q", got)
	}
}

func TestCORSOnlyAllowsConfiguredOrigins(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(CORS("https://app.example.com"))
	router.GET("/resource", func(ctx *gin.Context) { ctx.Status(http.StatusNoContent) })

	allowed := httptest.NewRequest(http.MethodOptions, "/resource", nil)
	allowed.Header.Set("Origin", "https://app.example.com")
	allowed.Header.Set("Access-Control-Request-Method", http.MethodGet)
	allowedRecorder := httptest.NewRecorder()
	router.ServeHTTP(allowedRecorder, allowed)
	if got := allowedRecorder.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("configured origin was not allowed: %q", got)
	}

	denied := httptest.NewRequest(http.MethodOptions, "/resource", nil)
	denied.Header.Set("Origin", "https://evil.example.com")
	denied.Header.Set("Access-Control-Request-Method", http.MethodGet)
	deniedRecorder := httptest.NewRecorder()
	router.ServeHTTP(deniedRecorder, denied)
	if got := deniedRecorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unexpected origin was allowed: %q", got)
	}
}
