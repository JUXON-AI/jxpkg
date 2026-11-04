package logtobff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/logto-io/go/v2/client"
)

type observedTransport struct {
	base    http.RoundTripper
	mu      sync.Mutex
	paths   map[string]int
	entered chan struct{}
	release chan struct{}
}

func (t *observedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.paths[r.URL.Path]++
	t.mu.Unlock()
	if r.URL.Path == "/api/my-account/organization-identity" && t.entered != nil {
		select {
		case t.entered <- struct{}{}:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		select {
		case <-t.release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	return t.base.RoundTrip(r)
}

func observeIdentity(t *testing.T, a *Runtime, block bool) *observedTransport {
	t.Helper()
	discovery, ok := a.http.Transport.(*discoveryTransport)
	if !ok {
		t.Fatal("missing metadata cache")
	}
	observer := &observedTransport{base: discovery.base, paths: map[string]int{}}
	if block {
		observer.entered, observer.release = make(chan struct{}, 8), make(chan struct{})
	}
	discovery.base = observer
	return observer
}

func TestIdentityOnlyWarmSessionUsesOneOnlineRequestAndRejectsScopes(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	if f.userInfoCalls.Load() != 0 || f.profileRequests.Load() == 0 {
		t.Fatal("login used userinfo instead of the online profile projection")
	}
	observer := observeIdentity(t, a, false)
	response := callAuth(a, "GET", "/auth/session", "", cookie, "")
	if response.Code != 200 || observer.paths["/api/my-account/organization-identity"] != 1 || len(observer.paths) != 1 || f.userInfoCalls.Load() != 0 {
		t.Fatal("warm session repeated token/profile/metadata requests")
	}
	body := sessionBody(t, response)
	csrf := body["csrf_token"].(string)
	router := gin.New()
	hits := 0
	router.POST("/protected", a.Require(), func(c *gin.Context) {
		p, ok := FromContext(c.Request.Context())
		if !ok || p.OrganizationID != "org-one" || len(p.DepartmentIDs) != 0 || p.PrimaryDepartmentID != nil || len(p.Permissions) != 0 {
			t.Error("pure identity invented authorization claims")
		}
		hits++
		c.Status(204)
	})
	router.POST("/scoped", a.Require("manage:credits"), func(c *gin.Context) { hits++; c.Status(204) })
	request := func(path string) int {
		r := httptest.NewRequest("POST", "http://localhost:5180"+path, nil)
		r.AddCookie(cookie)
		r.Header.Set("Origin", a.config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("X-Organization-ID", "org-one")
		r.Header.Set("X-Organization-Revision", "1")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w.Code
	}
	if request("/protected") != 204 || request("/scoped") != 403 || hits != 1 {
		t.Fatal("pure identity route or scope boundary changed")
	}
	f.denied = true
	if request("/protected") != 403 || hits != 1 {
		t.Fatal("cached user token bypassed current admission")
	}
}

func TestIdentityOnlyParallelRefreshOccursOnce(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	if f.userInfoCalls.Load() != 0 {
		t.Fatal("identity-only login issued UserInfo")
	}
	value, owner, err := a.store.acquire(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	var tokens map[string]client.AccessToken
	if err := json.Unmarshal([]byte(value.SDK[client.StorageKeyAccessTokenMap]), &tokens); err != nil {
		t.Fatal(err)
	}
	for key, token := range tokens {
		token.ExpiresAt = time.Now().Add(-time.Minute).Unix()
		tokens[key] = token
	}
	encoded, err := json.Marshal(tokens)
	if err != nil {
		t.Fatal(err)
	}
	value.SDK[client.StorageKeyAccessTokenMap] = string(encoded)
	if err := a.store.commit(context.Background(), cookie.Value, owner, cookie.Value, value, false); err != nil {
		t.Fatal(err)
	}
	observer := observeIdentity(t, a, true)
	beforeRefresh := f.refreshes
	var group sync.WaitGroup
	responses := make(chan int, 2)
	for range 2 {
		group.Go(func() { responses <- callAuth(a, "GET", "/auth/session", "", cookie, "").Code })
	}
	defer func() { close(observer.release); group.Wait() }()
	for range 2 {
		select {
		case <-observer.entered:
		case <-time.After(3 * time.Second):
			t.Fatal("online checks were serialized behind the session lease")
		}
	}
	// Both reads reached the authority before either finishes, while refresh remained serialized.
	if f.refreshes-beforeRefresh != 1 {
		t.Fatal("concurrent requests duplicated token refresh")
	}
	// Release and join here so the cleanup cannot double-close the gate.
	observer.release <- struct{}{}
	observer.release <- struct{}{}
	group.Wait()
	for range 2 {
		if code := <-responses; code != 200 {
			t.Fatalf("parallel unchanged session failed: %d", code)
		}
	}
	if f.userInfoCalls.Load() != 0 {
		t.Fatal("parallel online profile reads issued UserInfo")
	}
}

func identityAuthorityFixture() *session {
	now := time.Now()
	return &session{
		Subject:         "user-one",
		Organization:    "org-one",
		Revision:        "1",
		CSRF:            "csrf-one",
		Until:           now.Add(sessionIdleLifetime),
		PolicyVersion:   sessionPolicyVersion,
		AuthenticatedAt: now,
		IdleUntil:       now.Add(sessionIdleLifetime),
		AbsoluteUntil:   now.Add(sessionAbsoluteLifetime),
		SDK: map[string]string{
			client.StorageKeyIdToken:        "id-token",
			client.StorageKeyRefreshToken:   "refresh-token",
			client.StorageKeyAccessTokenMap: `{"@":{"token":"opaque-account-access","scope":"profile","expiresAt":4102444800}}`,
		},
	}
}

func identityAuthorityRuntime(endpoint string) *Runtime {
	return &Runtime{
		config: Config{Endpoint: endpoint, Origin: "http://localhost:5180", ClientID: "client-one"},
		http:   &http.Client{},
	}
}

func modelIdentityCommit(t *testing.T, stored, before, value *session, now time.Time) error {
	t.Helper()
	if err := mergeIdentityUpdate(stored, before, value, now); err != nil {
		return err
	}
	stored.Organization, stored.Revision, stored.CSRF = value.Organization, value.Revision, value.CSRF
	return nil
}

func TestSessionRenewalFailurePreservesOnlyOnTemporaryAuthorityOutage(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*fakeAuthority)
		status  int
		org     string
	}{
		{name: "temporary", prepare: func(f *fakeAuthority) { f.unavailable = true }, status: http.StatusServiceUnavailable, org: "org-one"},
		{name: "unauthorized", prepare: func(f *fakeAuthority) { f.identityInvalid = true }, status: http.StatusUnauthorized},
		{name: "forbidden", prepare: func(f *fakeAuthority) { f.denied = true }, status: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, endpoint := fixtureAuthority(t)
			tt.prepare(f)
			a := identityAuthorityRuntime(endpoint)
			value := identityAuthorityFixture()
			request := httptest.NewRequest(http.MethodPost, "http://localhost:5180/auth/session", strings.NewReader("{}"))
			request.Header.Set("Origin", "http://localhost:5180")
			request.Header.Set("X-CSRF-Token", value.CSRF)
			request.Header.Set("X-Organization-ID", value.Organization)
			request.Header.Set("X-Organization-Revision", value.Revision)
			result := a.renewSession(request, value)
			if result.status != tt.status {
				t.Fatalf("renewal status = %d, want %d", result.status, tt.status)
			}
			if value.Organization != tt.org {
				t.Fatalf("organization = %q, want %q", value.Organization, tt.org)
			}
		})
	}
}

func TestIdentityPreparationFailureHasDeterministicAuthorityAction(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		org    string
		remove bool
	}{
		{name: "temporary", err: errors.New("identity provider unavailable"), org: "org-one"},
		{name: "unauthorized", err: &accessError{status: http.StatusUnauthorized, code: "session_invalid"}, remove: true},
		{name: "forbidden", err: &accessError{status: http.StatusForbidden, code: "organization_access_denied"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := identityAuthorityFixture()
			if remove := applyIdentityPreparationFailure(value, tt.err); remove != tt.remove {
				t.Fatalf("remove = %t, want %t", remove, tt.remove)
			}
			if value.Organization != tt.org {
				t.Fatalf("organization = %q, want %q", value.Organization, tt.org)
			}
		})
	}
}

func TestCurrentRequestOnlyClearsAuthorityForRealRevocation(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*fakeAuthority)
		status  int
		org     string
	}{
		{name: "temporary", prepare: func(f *fakeAuthority) { f.unavailable = true }, status: http.StatusServiceUnavailable, org: "org-one"},
		{name: "unauthorized", prepare: func(f *fakeAuthority) { f.identityInvalid = true }, status: http.StatusUnauthorized},
		{name: "forbidden", prepare: func(f *fakeAuthority) { f.denied = true }, status: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, endpoint := fixtureAuthority(t)
			tt.prepare(f)
			a := identityAuthorityRuntime(endpoint)
			value := identityAuthorityFixture()
			_, _, err := a.currentRequest(context.Background(), value)
			if err == nil || classify(err).status != tt.status {
				t.Fatalf("current request error = %v", err)
			}
			if value.Organization != tt.org {
				t.Fatalf("organization = %q, want %q", value.Organization, tt.org)
			}
			if tt.org == "" && value.Revision != "1" {
				t.Fatalf("revision changed with organization revocation: %q", value.Revision)
			}
		})
	}
}

func TestTemporaryOrganizationReadDoesNotTurnSiblingIntoIdentityChange(t *testing.T) {
	_, endpoint := fixtureAuthority(t)
	a := identityAuthorityRuntime(endpoint)
	base := a.http.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	var calls atomic.Int64
	entered := make(chan int64, 2)
	failRelease, successRelease := make(chan struct{}), make(chan struct{})
	var failOnce, successOnce sync.Once
	releaseFail := func() { failOnce.Do(func() { close(failRelease) }) }
	releaseSuccess := func() { successOnce.Do(func() { close(successRelease) }) }
	t.Cleanup(releaseFail)
	t.Cleanup(releaseSuccess)
	a.http.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/api/my-account/organization-identity" {
			return base.RoundTrip(request)
		}
		call := calls.Add(1)
		select {
		case entered <- call:
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
		release := successRelease
		if call == 1 {
			release = failRelease
		}
		select {
		case <-release:
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
		if call == 1 {
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Status:     "503 Service Unavailable",
				Header:     make(http.Header),
				Body:       http.NoBody,
				Request:    request,
			}, nil
		}
		return base.RoundTrip(request)
	})

	type readResult struct {
		value *session
		err   error
	}
	failedRead, successfulRead := make(chan readResult, 1), make(chan readResult, 1)
	before := identityAuthorityFixture()
	stored := renewalClone(t, before)
	failedValue, successfulValue := renewalClone(t, before), renewalClone(t, before)
	go func() {
		_, _, err := a.currentRequest(context.Background(), failedValue)
		failedRead <- readResult{value: failedValue, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("temporary identity read did not reach the authority")
	}
	go func() {
		_, _, err := a.currentRequest(context.Background(), successfulValue)
		successfulRead <- readResult{value: successfulValue, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("sibling identity read did not reach the authority")
	}

	releaseFail()
	failed := <-failedRead
	if failed.err == nil || classify(failed.err).status != http.StatusServiceUnavailable {
		t.Fatalf("temporary read error = %v", failed.err)
	}
	if failed.value.Organization != "org-one" || failed.value.Revision != "1" {
		t.Fatalf("temporary read changed authority to organization=%q revision=%q", failed.value.Organization, failed.value.Revision)
	}
	if err := modelIdentityCommit(t, stored, before, failed.value, time.Now()); err != nil {
		t.Fatalf("temporary read failed its own commit fence: %v", err)
	}

	releaseSuccess()
	successful := <-successfulRead
	if successful.err != nil {
		t.Fatalf("sibling authority read failed: %v", successful.err)
	}
	if err := modelIdentityCommit(t, stored, before, successful.value, time.Now()); err != nil {
		t.Fatalf("temporary sibling commit failed: %v", err)
	}
	if stored.Organization != "org-one" || stored.Revision != "1" {
		t.Fatalf("sibling persisted organization=%q revision=%q", stored.Organization, stored.Revision)
	}
}

func TestIdentityOnlyPendingReadCannotReviveLogoutOrOverwriteRevision(t *testing.T) {
	for _, operation := range []string{"logout", "revision"} {
		t.Run(operation, func(t *testing.T) {
			a, f := fixtureRuntime(t, "")
			cookie := loginFixture(t, a, f)
			observer := observeIdentity(t, a, true)
			done := make(chan int, 1)
			go func() { defer close(done); done <- callAuth(a, "GET", "/auth/session", "", cookie, "").Code }()
			defer func() {
				close(observer.release)
				for range done {
				}
			}()
			select {
			case <-observer.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("request did not reach authority")
			}
			value, owner, err := a.store.acquire(context.Background(), cookie.Value)
			if err != nil {
				t.Fatal(err)
			}
			value.Revision = "2"
			if err := a.store.commit(context.Background(), cookie.Value, owner, cookie.Value, value, operation == "logout"); err != nil {
				t.Fatal(err)
			}
			observer.release <- struct{}{}
			code := <-done
			if (operation == "logout" && code != 401) || (operation == "revision" && code != 409) {
				t.Fatalf("old result survived state change: %d", code)
			}
			current, owner, err := a.store.acquire(context.Background(), cookie.Value)
			if operation == "logout" {
				if !errors.Is(err, _errMissing) {
					t.Fatal("read revived logged-out session")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer a.store.release(context.Background(), cookie.Value, owner)
			if current.Revision != "2" {
				t.Fatal("old read rewound current revision")
			}
		})
	}
}

func TestIdentityOnlyRevalidationAndDependencyFailure(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	expected := Principal{UserID: "user-one", OrganizationID: "org-one", OrganizationRevision: "1"}
	if err := a.revalidateIdentity(context.Background(), cookie.Value, expected, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.revalidateIdentity(context.Background(), cookie.Value, expected, []string{"anything"}); !errors.Is(err, ErrAuthorizationChanged) {
		t.Fatal("pure identity acquired resource scopes")
	}
	f.denied = true
	if err := a.revalidateIdentity(context.Background(), cookie.Value, expected, nil); !errors.Is(err, ErrAuthorizationChanged) {
		t.Fatal("sensitive result ignored online revocation")
	}
	f.denied = false
	f.unavailable = true
	if callAuth(a, "GET", "/auth/session", "", cookie, "").Code != 503 {
		t.Fatal("authority outage served cached identity")
	}
	f.unavailable = false
	f.identityInvalid = true
	if callAuth(a, "GET", "/auth/session", "", cookie, "").Code != 401 {
		t.Fatal("current user revocation ignored")
	}
	f.identityInvalid = false
	if callAuth(a, "GET", "/auth/session", "", cookie, "").Code != 401 {
		t.Fatal("revoked session revived")
	}
}

func TestIdentityOnlyStoredSubjectMustMatchVerifiedSDKIdentity(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	value, owner, err := a.store.acquire(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	value.Subject = "different-subject"
	if err := a.store.commit(context.Background(), cookie.Value, owner, cookie.Value, value, false); err != nil {
		t.Fatal(err)
	}
	if callAuth(a, "GET", "/auth/session", "", cookie, "").Code != 401 || callAuth(a, "GET", "/auth/session", "", cookie, "").Code != 401 {
		t.Fatal("stored subject replaced the authenticated SDK identity")
	}
}
