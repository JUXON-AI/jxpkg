package logtobff

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLogoutUnauthorizedClearsOnlyRejectedSession(t *testing.T) {
	for _, resource := range []string{"", "https://credits.invalid/api"} {
		name := "identity-only"
		if resource != "" {
			name = "resource"
		}
		t.Run(name, func(t *testing.T) {
			a, f := fixtureRuntime(t, resource)
			oldCookie := loginFixture(t, a, f)
			csrf := sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", oldCookie, ""))
			newCookie := loginFixture(t, a, f)
			before := storedSDKCredentials(t, a, newCookie)
			f.logoutStatus = http.StatusUnauthorized
			f.logoutResponseBody = "private-rejected-token-response"

			out := callAuth(a, "POST", "/auth/logout", "{}", oldCookie, csrf)
			if out.Code != http.StatusUnauthorized || !strings.Contains(out.Body.String(), `"session_invalid"`) || strings.Contains(out.Body.String(), f.logoutResponseBody) {
				t.Fatalf("rejected session logout status=%d", out.Code)
			}
			if callAuth(a, "GET", "/auth/session", "", oldCookie, "").Code != http.StatusUnauthorized {
				t.Fatal("rejected local session remained usable")
			}
			for key, value := range storedSDKCredentials(t, a, newCookie) {
				if value != before[key] {
					t.Fatal("old-session logout changed independent credentials")
				}
			}
			if callAuth(a, "GET", "/auth/session", "", newCookie, "").Code != http.StatusOK {
				t.Fatal("independent session was removed")
			}
			if f.logoutCalls != 1 || f.revokeCalls != 0 || f.endSessionCalls != 0 {
				t.Fatal("rejected logout retried or mutated a newer SSO session")
			}
		})
	}
}

func TestLogoutUnauthorizedCloseFailureKeepsLocal(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	csrf := sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
	before := storedSDKCredentials(t, a, cookie)
	base := a.http.Transport
	a.http.Transport = logoutFuncTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/my-account/browser-session/logout" {
			return base.RoundTrip(r)
		}
		return &http.Response{StatusCode: http.StatusUnauthorized, Header: make(http.Header), Body: logoutCloseErrorBody{}, Request: r}, nil
	})
	if out := callAuth(a, "POST", "/auth/logout", "{}", cookie, csrf); out.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfirmed response cleanup status=%d", out.Code)
	}
	for key, value := range storedSDKCredentials(t, a, cookie) {
		if value != before[key] {
			t.Fatal("response close failure changed credentials")
		}
	}
}

func TestLogoutUnauthorizedCannotRemoveNewerSessionState(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	csrf := sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
	base := a.http.Transport
	entered, release := make(chan struct{}), make(chan struct{})
	a.http.Transport = logoutFuncTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/my-account/browser-session/logout" {
			return base.RoundTrip(r)
		}
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return &http.Response{StatusCode: http.StatusUnauthorized, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("rejected")), Request: r}, nil
	})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- callAuth(a, "POST", "/auth/logout", "{}", cookie, csrf) }()
	defer close(release)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("logout did not reach authority")
	}
	current, owner, err := a.store.acquire(t.Context(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	newCSRF, err := a.store.opaque()
	if err != nil {
		a.store.release(t.Context(), cookie.Value, owner)
		t.Fatal(err)
	}
	current.CSRF = newCSRF
	if err := a.store.commit(t.Context(), cookie.Value, owner, cookie.Value, current, false); err != nil {
		t.Fatal(err)
	}
	release <- struct{}{}
	select {
	case out := <-done:
		if out.Code != http.StatusConflict {
			t.Fatalf("stale logout was not fenced: status=%d", out.Code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("logout did not finish")
	}
	if got := sessionCSRF(t, callAuth(a, "GET", "/auth/session", "", cookie, "")); got != newCSRF {
		t.Fatal("stale rejected logout removed newer state")
	}
}
