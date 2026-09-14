package sso

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JUXON-AI/jxpkg/apis/runtime"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/JUXON-AI/jxpkg/apis/runtime/server"
	"github.com/gin-gonic/gin"
)

func TestLoadLocalEnvCreatesIdentityTemplate(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), ".authjson")
	values := localTestEnv(authFile)

	got, err := LoadEnv(func(key string) string { return values[key] }, "JUXONONE")
	if got != nil || !errors.Is(err, auth.ErrAuthBackendUnavailable) || !strings.Contains(err.Error(), "fill user_id, uin and company_id") {
		t.Fatalf("LoadEnv() = %#v, %v", got, err)
	}
	info, err := os.Stat(authFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("template permissions = %o, want 600", info.Mode().Perm())
	}
	document, err := os.ReadFile(authFile)
	if err != nil {
		t.Fatal(err)
	}
	var identity DevIdentity
	if err := json.Unmarshal(document, &identity); err != nil || identity != (DevIdentity{}) {
		t.Fatalf("template = %s, %v", document, err)
	}
}

func TestDevIdentityFlagValue(t *testing.T) {
	var identity DevIdentity
	if identity.String() != "" || identity.Type() != "user_id:uin:company_id" {
		t.Fatalf("zero identity = %q/%q", identity.String(), identity.Type())
	}
	if err := identity.Set("11:22:33"); err != nil {
		t.Fatal(err)
	}
	if identity != (DevIdentity{UserID: 11, UIN: 22, CompanyID: 33}) || identity.String() != "11:22:33" {
		t.Fatalf("identity = %#v/%q", identity, identity.String())
	}
	for _, value := range []string{"", "1", "1:2", "1:2:3:4", "0:2:3", "1:x:3", "-1:2:3"} {
		t.Run(value, func(t *testing.T) {
			previous := identity
			if err := identity.Set(value); err == nil {
				t.Fatalf("Set(%q) expected error", value)
			}
			if identity != previous {
				t.Fatalf("Set(%q) partially updated identity to %#v", value, identity)
			}
		})
	}
}

func TestDevIdentityOptionUsesSharedRuntimeWithoutFile(t *testing.T) {
	values := map[string]string{}
	localRuntime, err := LoadEnv(
		func(key string) string { return values[key] },
		"JXX",
		WithHTTPAddress(":8080"),
		WithDevIdentity(DevIdentity{UserID: 11, UIN: 22, CompanyID: 33}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer localRuntime.Close()
	if localRuntime.HTTPAddress() != "127.0.0.1:8080" || localRuntime.Origin() != "http://localhost:5173" {
		t.Fatalf("runtime address/origin = %q/%q", localRuntime.HTTPAddress(), localRuntime.Origin())
	}

	router := server.NewRouter("/v1/", localRuntime.RouterOption())
	router.PRequireBrowserSession("protected", gin.HandlerFunc(func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"uin": runtime.UIN(ctx)})
	}))
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/v1/protected", nil)
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set(localIdentityHeader, "active")
	recorder := httptest.NewRecorder()
	router.GinEngine().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != `{"uin":22}` {
		t.Fatalf("status/body = %d/%s", recorder.Code, recorder.Body.String())
	}
}

func TestRuntimeOptionsRejectInvalidValues(t *testing.T) {
	getenv := func(string) string { return "" }
	for _, test := range []struct {
		name   string
		option RuntimeOption
	}{
		{name: "nil option", option: nil},
		{name: "empty HTTP address", option: WithHTTPAddress("")},
		{name: "partial identity", option: WithDevIdentity(DevIdentity{UserID: 1})},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := LoadEnv(getenv, "JXX", test.option)
			if got != nil || !errors.Is(err, auth.ErrAuthBackendUnavailable) {
				t.Fatalf("LoadEnv() = %#v, %v", got, err)
			}
		})
	}
}

func TestLocalRuntimeAuthenticatesExistingBrowserRoutes(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), ".authjson")
	if err := os.WriteFile(authFile, []byte(`{"user_id":11,"uin":22,"company_id":33}`), 0o600); err != nil {
		t.Fatal(err)
	}
	values := localTestEnv(authFile)
	localRuntime, err := LoadEnv(func(key string) string { return values[key] }, "JUXONONE")
	if err != nil {
		t.Fatal(err)
	}
	defer localRuntime.Close()

	router := server.NewRouter("/v1/", localRuntime.RouterOption())
	router.PRequireBrowserSession("protected", gin.HandlerFunc(func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"user_id": runtime.UserID(ctx), "uin": runtime.UIN(ctx), "company_id": runtime.CompanyID(ctx),
		})
	}))

	for _, test := range []struct {
		name          string
		header        []string
		authorization string
		cookie        bool
		remoteAddress string
		wantStatus    int
	}{
		{name: "active identity", header: []string{"active"}, remoteAddress: "127.0.0.1:54321", wantStatus: http.StatusOK},
		{name: "exact UIN", header: []string{"22"}, remoteAddress: "[::1]:54321", wantStatus: http.StatusOK},
		{name: "missing header", remoteAddress: "127.0.0.1:54321", wantStatus: http.StatusUnauthorized},
		{name: "wrong UIN", header: []string{"23"}, remoteAddress: "127.0.0.1:54321", wantStatus: http.StatusUnauthorized},
		{name: "duplicate header", header: []string{"active", "active"}, remoteAddress: "127.0.0.1:54321", wantStatus: http.StatusUnauthorized},
		{name: "ambiguous bearer", header: []string{"active"}, authorization: "Bearer token", remoteAddress: "127.0.0.1:54321", wantStatus: http.StatusUnauthorized},
		{name: "synthetic cookie without header", cookie: true, remoteAddress: "127.0.0.1:54321", wantStatus: http.StatusUnauthorized},
		{name: "remote request", header: []string{"active"}, remoteAddress: "192.0.2.1:54321", wantStatus: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://localhost:5173/v1/protected", nil)
			request.RemoteAddr = test.remoteAddress
			for _, value := range test.header {
				request.Header.Add(localIdentityHeader, value)
			}
			if test.authorization != "" {
				request.Header.Set("Authorization", test.authorization)
			}
			if test.cookie {
				request.AddCookie(&http.Cookie{Name: localCookieName, Value: localSessionID})
			}
			recorder := httptest.NewRecorder()
			router.GinEngine().ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if test.wantStatus == http.StatusOK && recorder.Body.String() != `{"company_id":33,"uin":22,"user_id":11}` {
				t.Fatalf("body = %s", recorder.Body.String())
			}
		})
	}
}

func TestLocalRuntimeProvidesFrontendBootstrapAndCompanyIdentity(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), ".authjson")
	if err := os.WriteFile(authFile, []byte(`{"user_id":11,"uin":22,"company_id":33}`), 0o600); err != nil {
		t.Fatal(err)
	}
	values := localTestEnv(authFile)
	localRuntime, err := LoadEnv(func(key string) string { return values[key] }, "JUXONONE")
	if err != nil {
		t.Fatal(err)
	}
	defer localRuntime.Close()

	router := server.NewRouter("/v1/", localRuntime.RouterOption())
	request := httptest.NewRequest(http.MethodGet, "http://localhost:5173/auth/session", nil)
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set(localIdentityHeader, "active")
	recorder := httptest.NewRecorder()
	router.GinEngine().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("session status/cache = %d/%q; body = %s", recorder.Code, recorder.Header().Get("Cache-Control"), recorder.Body.String())
	}
	var session struct {
		Authenticated bool `json:"authenticated"`
		UserID        uint `json:"user_id"`
		Identity      struct {
			UIN       uint   `json:"uin"`
			CompanyID uint   `json:"company_id"`
			Username  string `json:"username"`
		} `json:"identity"`
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &session); err != nil || !session.Authenticated || session.UserID != 11 ||
		session.Identity.UIN != 22 || session.Identity.CompanyID != 33 || session.Identity.Username == "" || session.CSRFToken == "" {
		t.Fatalf("session = %#v, %v", session, err)
	}

	identities, err := localRuntime.CompanyIdentityResolver().ResolveCompanyIdentities(context.Background(), auth.CompanyIdentityResolveRequest{
		Service: "juxonone", CompanyID: 33, UINs: []uint{22, 44},
	})
	if err != nil || len(identities) != 1 || identities[0].UIN != 22 || identities[0].Status != auth.CompanyIdentityStatusActive {
		t.Fatalf("ResolveCompanyIdentities() = %#v, %v", identities, err)
	}
	authorization, err := localRuntime.AuthorizationContextResolver().ResolveAuthorizationContext(context.Background(), auth.AuthorizationContextResolveRequest{
		Service: "jxagent", CompanyID: 33, UIN: 22, MembershipEpoch: 1, Permissions: []auth.PermissionCode{"agent.create"},
	})
	if err != nil || !authorization.IsCompanyOwner || !authorization.Allows("agent.create") {
		t.Fatalf("ResolveAuthorizationContext() = %#v, %v", authorization, err)
	}
	subjects, err := localRuntime.AuthorizationSubjectsResolver().ResolveAuthorizationSubjects(context.Background(), auth.AuthorizationSubjectsResolveRequest{
		Service: "jxagent", CompanyID: 33, UIN: 22, MembershipEpoch: 1,
	})
	if err != nil || len(subjects.Users) != 1 || subjects.Users[0].UIN != 22 {
		t.Fatalf("ResolveAuthorizationSubjects() = %#v, %v", subjects, err)
	}
}

func TestLocalRuntimeFailsClosedOutsideExplicitLoopbackMode(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), ".authjson")
	if err := os.WriteFile(authFile, []byte(`{"user_id":11,"uin":22,"company_id":33}`), 0o600); err != nil {
		t.Fatal(err)
	}
	base := localTestEnv(authFile)
	for _, test := range []struct {
		name  string
		key   string
		value string
	}{
		{name: "Kubernetes", key: "KUBERNETES_SERVICE_HOST", value: "10.0.0.1"},
		{name: "non-loopback listener", key: "JUXONONE_HTTP_ADDR", value: "0.0.0.0:8080"},
		{name: "TLS origin", key: "JUXONONE_EXTERNAL_ORIGIN", value: "https://localhost:5173"},
		{name: "invalid mode", key: "JUXONONE_SSO_MODE", value: "debug"},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := make(map[string]string, len(base))
			for key, value := range base {
				values[key] = value
			}
			values[test.key] = test.value
			got, err := LoadEnv(func(key string) string { return values[key] }, "JUXONONE")
			if got != nil || !errors.Is(err, auth.ErrAuthBackendUnavailable) {
				t.Fatalf("LoadEnv() = %#v, %v", got, err)
			}
		})
	}
}

func localTestEnv(authFile string) map[string]string {
	return map[string]string{
		"JUXONONE_SSO_MODE":                 "local",
		"JUXONONE_SSO_DEV_AUTH_FILE":        authFile,
		"JUXONONE_HTTP_ADDR":                "127.0.0.1:8080",
		"JUXONONE_EXTERNAL_ORIGIN":          "http://localhost:5173",
		"JUXONONE_SESSION_RESOLVER_SERVICE": "juxonone",
	}
}
