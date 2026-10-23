package logtobff

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/logto-io/go/v2/client"
)

// logoutGateTransport lets both identity snapshots reach the center before either reply.
type logoutGateTransport struct {
	base    http.RoundTripper
	entered chan chan struct{}
	stop    context.Context
}

func (p *logoutGateTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path != "/api/my-account/browser-session/logout" {
		return p.base.RoundTrip(r)
	}
	gate := make(chan struct{})
	select {
	case p.entered <- gate:
	case <-r.Context().Done():
		return nil, r.Context().Err()
	case <-p.stop.Done():
		return nil, p.stop.Err()
	}
	select {
	case <-gate:
	case <-r.Context().Done():
		return nil, r.Context().Err()
	case <-p.stop.Done():
		return nil, p.stop.Err()
	}
	return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("center-down")), Request: r}, nil
}

func TestLogoutConcurrentUnavailableKeepsBothFailures(t *testing.T) {
	var (
		a, f    = fixtureRuntime(t, "")
		cookie  = loginFixture(t, a, f)
		csrf    = sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
		before  = storedSDKCredentials(t, a, cookie)
		p       = &logoutGateTransport{base: a.http.Transport, entered: make(chan chan struct{}), stop: t.Context()}
		done    = make(chan *httptest.ResponseRecorder)
		workers sync.WaitGroup
	)
	t.Cleanup(workers.Wait)
	a.http.Transport = p
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			out := callAuth(a, "POST", "/auth/logout", "{}", cookie, csrf)
			select {
			case done <- out:
			case <-t.Context().Done():
			}
		}()
	}
	var gates [2]chan struct{}
	for i := range gates {
		select {
		case gates[i] = <-p.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent logout did not reach center")
		}
	}
	for _, gate := range gates {
		close(gate)
		select {
		case out := <-done:
			if out.Code != http.StatusServiceUnavailable || !strings.Contains(out.Body.String(), `"browser_logout_unavailable"`) {
				t.Errorf("center failure became HTTP %d: %s", out.Code, out.Body.String())
			}
		case <-time.After(5 * time.Second):
			t.Fatal("center failure did not finish; possible mutation replay")
		}
	}
	after := storedSDKCredentials(t, a, cookie)
	for key, value := range before {
		if value == "" || after[key] != value {
			t.Errorf("center failure changed SDK credential %s", key)
		}
	}
	if out := callAuth(a, "GET", "/auth/session", "", cookie, ""); out.Code != http.StatusOK {
		t.Errorf("center failures removed local session: %d", out.Code)
	}
	if f.logoutCalls != 0 || f.revokeCalls != 0 || f.endSessionCalls != 0 {
		t.Fatal("center failure repeated mutation or revoked a grant")
	}
}

type logoutFuncTransport func(*http.Request) (*http.Response, error)

func (p logoutFuncTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return p(r)
}

func TestLogoutUnknownStatusesKeepLocal(t *testing.T) {
	for _, status := range []int{200, 201, 202, 301, 302, 303, 307, 308, 400, 401, 403, 404, 409, 429, 500, 502, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var (
				a, f   = fixtureRuntime(t)
				cookie = loginFixture(t, a, f)
				csrf   = sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
			)
			f.logoutStatus = status
			f.logoutResponseBody = "private-response"
			if out := callAuth(a, "POST", "/auth/logout", "{}", cookie, csrf); out.Code != http.StatusServiceUnavailable || strings.Contains(out.Body.String(), f.logoutResponseBody) {
				t.Fatalf("status=%d out=%d", status, out.Code)
			}
			if out := callAuth(a, "GET", "/auth/session", "", cookie, ""); out.Code != http.StatusOK {
				t.Fatalf("status=%d lost local capability: %d", status, out.Code)
			}
			if f.logoutCalls != 1 || f.revokeCalls != 0 || f.endSessionCalls != 0 {
				t.Fatal("unknown response repeated mutation or revoked a grant")
			}
		})
	}
}

type logoutCloseErrorBody struct{}

func (logoutCloseErrorBody) Read([]byte) (int, error) { return 0, io.EOF }
func (logoutCloseErrorBody) Close() error             { return errors.New("synthetic-close-error") }

func TestLogoutCloseErrorKeepsLocal(t *testing.T) {
	for _, resource := range []string{"", "https://credits.invalid/api"} {
		var (
			a, f   = fixtureRuntime(t, resource)
			cookie = loginFixture(t, a, f)
			csrf   = sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
			base   = a.http.Transport
		)
		a.http.Transport = logoutFuncTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/api/my-account/browser-session/logout" {
				return base.RoundTrip(r)
			}
			return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: logoutCloseErrorBody{}, Request: r}, nil
		})
		if out := callAuth(a, "POST", "/auth/logout", "{}", cookie, csrf); out.Code != http.StatusServiceUnavailable {
			t.Fatal("close error accepted", out.Code)
		}
		if out := callAuth(a, "GET", "/auth/session", "", cookie, ""); out.Code != http.StatusOK {
			t.Fatal("close error removed local capability", out.Code)
		}
	}
}

func TestLogoutUsesNarrowBrowserSessionEndpoint(t *testing.T) {
	for _, resource := range []string{"", "https://credits.invalid/api"} {
		name := "identity-only"
		if resource != "" {
			name = "resource"
		}
		t.Run(name, func(t *testing.T) {
			var (
				a, f   = fixtureRuntime(t, resource)
				cookie = loginFixture(t, a, f)
				before = storedSDKCredentials(t, a, cookie)
			)
			if before[client.StorageKeyRefreshToken] == "" {
				t.Fatal("fixture refresh token absent")
			}
			csrf := sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))

			out := callAuth(a, "POST", "/auth/logout", `{"unexpected":"body"}`, cookie, csrf)
			if out.Code != http.StatusOK {
				t.Fatalf("logout HTTP %d: %s", out.Code, out.Body.String())
			}
			if redirect := sessionBody(t, out)["redirect_uri"]; redirect != a.config.Origin+"/" {
				t.Fatalf("logout redirect %q", redirect)
			}
			if f.logoutCalls != 1 || f.logoutMethod != http.MethodPost || f.logoutPath != "/api/my-account/browser-session/logout" {
				t.Fatalf("center call method=%q path=%q calls=%d", f.logoutMethod, f.logoutPath, f.logoutCalls)
			}
			if f.logoutAuthorization != "Bearer opaque-account-access" || f.logoutBody != "" {
				t.Fatalf("center authorization/body invalid")
			}
			if f.revokeCalls != 0 || f.endSessionCalls != 0 {
				t.Fatalf("logout revoked grant or called end-session")
			}
			if callAuth(a, "GET", "/auth/session", "", cookie, "").Code != http.StatusUnauthorized {
				t.Fatal("confirmed center logout kept local session")
			}
		})
	}
}

func TestLogoutRejectsUnboundOriginAndCSRF(t *testing.T) {
	var (
		a, f   = fixtureRuntime(t)
		cookie = loginFixture(t, a, f)
		csrf   = sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
	)

	for name, headers := range map[string][2]string{
		"origin": {a.config.Origin + ".invalid", csrf},
		"csrf":   {a.config.Origin, csrf + "x"},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, a.config.Origin+"/auth/logout", nil)
			r.AddCookie(cookie)
			r.Header.Set("Origin", headers[0])
			r.Header.Set("X-CSRF-Token", headers[1])
			w := httptest.NewRecorder()
			a.Handler().ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("logout HTTP %d", w.Code)
			}
		})
	}
	if f.logoutCalls != 0 || f.revokeCalls != 0 || f.endSessionCalls != 0 {
		t.Fatal("rejected logout reached center or revocation")
	}
}

func TestLogoutServerFailureKeepsLocalSession(t *testing.T) {
	for _, resource := range []string{"", "https://credits.invalid/api"} {
		name := "identity-only"
		if resource != "" {
			name = "resource"
		}
		t.Run(name, func(t *testing.T) {
			var (
				a, f   = fixtureRuntime(t, resource)
				cookie = loginFixture(t, a, f)
				csrf   = sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
				before = storedSDKCredentials(t, a, cookie)
			)
			f.logoutStatus = http.StatusServiceUnavailable
			f.logoutResponseBody = "private-upstream-response"

			if out := callAuth(a, "POST", "/auth/logout", `{}`, cookie, csrf); out.Code != http.StatusServiceUnavailable || !strings.Contains(out.Body.String(), `"browser_logout_unavailable"`) || strings.Contains(out.Body.String(), f.logoutResponseBody) {
				t.Fatalf("logout HTTP %d: %s", out.Code, out.Body.String())
			}
			after := storedSDKCredentials(t, a, cookie)
			for _, key := range []string{client.StorageKeyRefreshToken, client.StorageKeyAccessTokenMap, client.StorageKeyIdToken} {
				if before[key] == "" || after[key] != before[key] {
					t.Fatalf("center failure cleared %s", key)
				}
			}
			if sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))["authenticated"] != true {
				t.Fatal("center failure removed local session")
			}
			if f.logoutCalls != 1 || f.revokeCalls != 0 || f.endSessionCalls != 0 {
				t.Fatal("center failure repeated mutation or revoked a grant")
			}
		})
	}
}

func TestLogoutTimeoutKeepsLocalSession(t *testing.T) {
	for _, resource := range []string{"", "https://credits.invalid/api"} {
		name := "identity-only"
		if resource != "" {
			name = "resource"
		}
		t.Run(name, func(t *testing.T) {
			var (
				a, f   = fixtureRuntime(t, resource)
				cookie = loginFixture(t, a, f)
				csrf   = sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
				before = storedSDKCredentials(t, a, cookie)
			)
			f.logoutBlock = true
			a.http.Timeout = 25 * time.Millisecond

			if out := callAuth(a, "POST", "/auth/logout", `{}`, cookie, csrf); out.Code != http.StatusServiceUnavailable {
				t.Fatalf("logout HTTP %d", out.Code)
			}
			after := storedSDKCredentials(t, a, cookie)
			if after[client.StorageKeyRefreshToken] != before[client.StorageKeyRefreshToken] || after[client.StorageKeyAccessTokenMap] != before[client.StorageKeyAccessTokenMap] {
				t.Fatal("center timeout cleared SDK credentials")
			}
			if sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))["authenticated"] != true {
				t.Fatal("center timeout removed local session")
			}
			if f.logoutCalls != 1 {
				t.Fatal("center timeout was automatically replayed")
			}
		})
	}
}

func TestLogoutResponseLossReconcilesOnNextSession(t *testing.T) {
	for _, resource := range []string{"", "https://credits.invalid/api"} {
		name := "identity-only"
		if resource != "" {
			name = "resource"
		}
		t.Run(name, func(t *testing.T) {
			var (
				a, f   = fixtureRuntime(t, resource)
				cookie = loginFixture(t, a, f)
				csrf   = sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
			)
			f.logoutCommitLost = true

			if out := callAuth(a, "POST", "/auth/logout", `{}`, cookie, csrf); out.Code != http.StatusServiceUnavailable {
				t.Fatalf("logout HTTP %d", out.Code)
			}
			if callAuth(a, "GET", "/auth/session", "", cookie, "").Code != http.StatusUnauthorized {
				t.Fatal("next session did not reconcile committed center logout")
			}
			if callAuth(a, "GET", "/auth/session", "", cookie, "").Code != http.StatusUnauthorized {
				t.Fatal("reconciled local session revived")
			}
			if f.logoutCalls != 1 {
				t.Fatal("reconcile automatically repeated the center mutation")
			}
		})
	}
}

func TestLogoutConsumesSharedNativeSessionAcrossBFFs(t *testing.T) {
	for _, resource := range []string{"", "https://credits.invalid/api"} {
		name := "identity-only"
		if resource != "" {
			name = "resource"
		}
		t.Run(name, func(t *testing.T) {
			var (
				private     = loadFixtureRedisConfig(t)
				f, endpoint = fixtureAuthority(t)
				a           = fixtureRuntimeWithAuthority(t, endpoint, private, "mcphub_a", resource)
				b           = fixtureRuntimeWithAuthority(t, endpoint, private, "mcphub_b", resource)
				c           = fixtureRuntimeWithAuthority(t, endpoint, private, "mcphub_c", resource)
				aCookie     = loginFixture(t, a, f)
				bCookie     = loginFixture(t, b, f)
				cCookie     = loginFixture(t, c, f)
				aCSRF       = sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", aCookie, ""))
				cCSRF       = sessionCSRF(t, callAuth(c, "GET", "/auth/session", "", cCookie, ""))
			)

			if out := callAuth(a, "POST", "/auth/logout", `{}`, aCookie, aCSRF); out.Code != http.StatusOK {
				t.Fatalf("logout HTTP %d", out.Code)
			}
			if callAuth(b, "GET", "/auth/session", "", bCookie, "").Code != http.StatusUnauthorized {
				t.Fatal("second BFF session survived shared native-session consumption")
			}
			if requireStatus(t, c, cCookie, cCSRF) != http.StatusUnauthorized {
				t.Fatal("Require survived shared native-session consumption")
			}
			if f.logoutCalls != 1 || f.revokeCalls != 0 || f.endSessionCalls != 0 {
				t.Fatal("BFF session checks repeated mutation or revoked a grant")
			}
		})
	}
}

func requireStatus(t *testing.T, a *Runtime, cookie *http.Cookie, csrf string) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/protected", a.Require(), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	r := httptest.NewRequest(http.MethodPost, a.config.Origin+"/protected", nil)
	r.AddCookie(cookie)
	r.Header.Set("Origin", a.config.Origin)
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("X-Organization-ID", "org-one")
	r.Header.Set("X-Organization-Revision", "1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w.Code
}

func sessionCSRF(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	csrf, ok := sessionBody(t, response)["csrf_token"].(string)
	if !ok || csrf == "" {
		t.Fatal("session CSRF absent")
	}
	return csrf
}

func storedSDKCredentials(t *testing.T, a *Runtime, cookie *http.Cookie) map[string]string {
	t.Helper()
	value, owner, err := a.store.acquire(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	defer a.store.release(context.Background(), cookie.Value, owner)
	return map[string]string{
		client.StorageKeyRefreshToken:   value.SDK[client.StorageKeyRefreshToken],
		client.StorageKeyAccessTokenMap: value.SDK[client.StorageKeyAccessTokenMap],
		client.StorageKeyIdToken:        value.SDK[client.StorageKeyIdToken],
	}
}
