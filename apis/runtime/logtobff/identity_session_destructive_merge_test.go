package logtobff

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/logto-io/go/v2/client"
)

func TestDelayedIdentity401CannotRemoveConcurrentSDK(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	original := renewalReadSession(t, a, cookie)
	f.identityInvalid = true
	entered, release := blockAuthorityPath(t, a, "/api/my-account/organization-identity")
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		defer close(response)
		response <- callAuth(a, http.MethodGet, "/auth/session", "", cookie, "")
	}()
	waitForAuthority(t, entered)
	rotated := rotateStoredSDK(t, a, cookie, "refresh-concurrent-session")
	close(release)
	if got := <-response; got.Code != http.StatusConflict || len(got.Result().Cookies()) != 0 {
		t.Fatalf("stale invalidation HTTP %d cookies=%v", got.Code, got.Result().Cookies())
	}
	assertConcurrentSDKPreserved(t, a, cookie, original.CSRF, rotated)
	f.identityInvalid = false
	if got := callAuth(a, http.MethodGet, "/auth/session", "", cookie, "").Code; got != http.StatusOK {
		t.Fatalf("rotated session did not recover HTTP %d", got)
	}
}

func TestSensitiveRevalidationRejectsStale401WithoutRemovingConcurrentSDK(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	original := renewalReadSession(t, a, cookie)
	expected := Principal{UserID: original.Subject, OrganizationID: original.Organization, OrganizationRevision: original.Revision}
	f.identityInvalid = true
	entered, release := blockAuthorityPath(t, a, "/api/my-account/organization-identity")
	result := make(chan error, 1)
	go func() {
		result <- a.revalidateIdentity(context.Background(), cookie.Value, expected, nil)
	}()
	waitForAuthority(t, entered)
	rotated := rotateStoredSDK(t, a, cookie, "refresh-concurrent-revalidate")
	close(release)
	if err := <-result; !errors.Is(err, ErrAuthorizationChanged) {
		t.Fatalf("stale sensitive revalidation error %v", err)
	}
	assertConcurrentSDKPreserved(t, a, cookie, original.CSRF, rotated)
	f.identityInvalid = false
	if got := callAuth(a, http.MethodGet, "/auth/session", "", cookie, "").Code; got != http.StatusOK {
		t.Fatalf("revalidated session did not recover HTTP %d", got)
	}
}

func TestResourceGrantDestructiveFinishCannotRemoveConcurrentSDK(t *testing.T) {
	a, f := fixtureRuntime(t)
	cookie := loginFixture(t, a, f)
	original := renewalReadSession(t, a, cookie)
	expected := Principal{UserID: original.Subject, OrganizationID: original.Organization, OrganizationRevision: original.Revision}
	f.userInvalid = true
	entered, release := blockAuthorityPath(t, a, "/oidc/me")
	result := make(chan error, 1)
	go func() {
		result <- a.revokeResourceGrant(context.Background(), cookie.Value, expected, "https://hub.invalid/mcp", "grant-one")
	}()
	waitForAuthority(t, entered)
	rotated := rotateStoredSDK(t, a, cookie, "refresh-concurrent-resource-grant")
	close(release)
	if err := <-result; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("stale resource-grant invalidation error %v", err)
	}
	assertConcurrentSDKPreserved(t, a, cookie, original.CSRF, rotated)
	f.userInvalid = false
	if got := callAuth(a, http.MethodGet, "/auth/session", "", cookie, "").Code; got != http.StatusOK {
		t.Fatalf("resource session did not recover HTTP %d", got)
	}
}

func TestSameGenerationIdentity401StillRemovesSession(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	f.identityInvalid = true
	response := callAuth(a, http.MethodGet, "/auth/session", "", cookie, "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("current-generation invalidation HTTP %d", response.Code)
	}
	deleted := false
	for _, candidate := range response.Result().Cookies() {
		if candidate.Name == a.config.CookieName && candidate.MaxAge < 0 {
			deleted = true
		}
	}
	if !deleted {
		t.Fatal("current-generation invalidation did not clear the browser cookie")
	}
	if _, _, err := a.store.acquire(context.Background(), cookie.Value); !errors.Is(err, _errMissing) {
		t.Fatalf("current-generation invalidation retained Redis state: %v", err)
	}
}

func rotateStoredSDK(t *testing.T, a *Runtime, cookie *http.Cookie, refresh string) *session {
	t.Helper()
	value, owner, err := a.store.acquire(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	defer a.store.release(context.Background(), cookie.Value, owner)
	value.SDK[client.StorageKeyRefreshToken] = refresh
	if err := a.store.commit(context.Background(), cookie.Value, owner, cookie.Value, value, false); err != nil {
		t.Fatal(err)
	}
	return renewalClone(t, value)
}

func assertConcurrentSDKPreserved(t *testing.T, a *Runtime, cookie *http.Cookie, csrf string, rotated *session) {
	t.Helper()
	stored := renewalReadSession(t, a, cookie)
	if stored.SDK[client.StorageKeyRefreshToken] != rotated.SDK[client.StorageKeyRefreshToken] || stored.CSRF != csrf {
		t.Fatal("stale destructive result removed or rewound the concurrent SDK state")
	}
}

func blockAuthorityPath(t *testing.T, a *Runtime, path string) (<-chan struct{}, chan struct{}) {
	t.Helper()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	base := a.http.Transport
	a.http.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == path {
			select {
			case entered <- struct{}{}:
			case <-request.Context().Done():
				return nil, request.Context().Err()
			}
			select {
			case <-release:
			case <-request.Context().Done():
				return nil, request.Context().Err()
			}
		}
		return base.RoundTrip(request)
	})
	return entered, release
}

func waitForAuthority(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not reach the authority")
	}
}
