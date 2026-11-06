package logtobff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/identity"
	"github.com/gin-gonic/gin"
)

func TestAuthorizedContextPublishesDisplayNamesForSameMember(t *testing.T) {
	runtime := &Runtime{}
	principal := Principal{
		UserID:           "user-one",
		OrganizationID:   "org-one",
		Username:         "user-one",
		OrganizationName: "Company One",
		ExpiresAt:        time.Now().Add(time.Minute).Unix(),
	}
	ctx := runtime.authorizedContext(context.Background(), "session-one", principal)
	got, ok := FromContext(ctx)
	if !ok || got.UserID != principal.UserID || got.OrganizationID != principal.OrganizationID || got.Username != principal.Username || got.OrganizationName != principal.OrganizationName {
		t.Fatalf("principal = %#v, %v", got, ok)
	}
	names, ok := identity.DisplayNamesFromContext(ctx, identity.Member{OrganizationID: "org-one", UserID: "user-one"})
	if !ok || names.Username != "user-one" || names.OrganizationName != "Company One" {
		t.Fatalf("display names = %#v, %v", names, ok)
	}
	for _, other := range []identity.Member{
		{OrganizationID: "org-two", UserID: "user-one"},
		{OrganizationID: "org-one", UserID: "user-two"},
	} {
		if names, ok := identity.DisplayNamesFromContext(ctx, other); ok || names != (identity.DisplayNames{}) {
			t.Fatalf("display names crossed member boundary %#v: %#v, %v", other, names, ok)
		}
	}
}

func TestAuthorizedContextOmitsIncompleteDisplayNamesWithoutDenyingPrincipal(t *testing.T) {
	runtime := &Runtime{}
	username, organizationName := principalDisplayNames(profile{}, []organization{{ID: "org-one", Name: "Company One"}}, "org-one")
	principal := Principal{
		UserID:           "user-one",
		OrganizationID:   "org-one",
		Username:         username,
		OrganizationName: organizationName,
		ExpiresAt:        time.Now().Add(time.Minute).Unix(),
	}
	ctx := runtime.authorizedContext(context.Background(), "session-one", principal)
	if got, ok := FromContext(ctx); !ok || got.UserID != principal.UserID || got.OrganizationID != principal.OrganizationID || got.Username != "" || got.OrganizationName != "" {
		t.Fatalf("principal = %#v, %v", got, ok)
	}
	assertPrincipalDisplayNamesConsistency(t, ctx, principal)
}

func TestPrincipalDisplayNamesUseUsernameAndMatchingOrganization(t *testing.T) {
	tests := []struct {
		name             string
		profile          profile
		organizations    []organization
		wantUsername     string
		wantOrganization string
	}{
		{
			name:             "trim complete pair",
			profile:          profile{Username: "  user-one  ", Name: "ignored"},
			organizations:    []organization{{ID: "org-two", Name: "Company Two"}, {ID: "org-one", Name: "  Company One  "}},
			wantUsername:     "user-one",
			wantOrganization: "Company One",
		},
		{
			name:          "control",
			profile:       profile{Username: "user\u0001one"},
			organizations: []organization{{ID: "org-one", Name: "Company One"}},
		},
		{
			name:          "oversized",
			profile:       profile{Username: strings.Repeat("u", 513)},
			organizations: []organization{{ID: "org-one", Name: "Company One"}},
		},
		{
			name:          "invalid UTF-8",
			profile:       profile{Username: string([]byte{0xff})},
			organizations: []organization{{ID: "org-one", Name: "Company One"}},
		},
		{
			name:          "whitespace-only username does not fall back",
			profile:       profile{Username: "   ", Name: "Synthetic member"},
			organizations: []organization{{ID: "org-one", Name: "Company One"}},
		},
		{
			name:          "missing matching organization",
			profile:       profile{Username: "user-one"},
			organizations: []organization{{ID: "org-two", Name: "Company Two"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username, organizationName := principalDisplayNames(tt.profile, tt.organizations, "org-one")
			if username != tt.wantUsername || organizationName != tt.wantOrganization {
				t.Fatalf("display names = %q, %q; want %q, %q", username, organizationName, tt.wantUsername, tt.wantOrganization)
			}
		})
	}
}

func TestPrincipalDisplayNamesFallbackToProfileName(t *testing.T) {
	username, organizationName := principalDisplayNames(
		profile{Name: "Synthetic member"},
		[]organization{{ID: "org-one", Name: "Company One"}},
		"org-one",
	)
	if username != "Synthetic member" || organizationName != "Company One" {
		t.Fatalf("fallback display names = %q, %q", username, organizationName)
	}
}

func TestAuthorizedContextMatchesCanonicalDisplayNames(t *testing.T) {
	for _, tt := range []struct {
		name    string
		profile profile
	}{
		{name: "trimmed", profile: profile{Username: "  user-one  "}},
		{name: "control", profile: profile{Username: "user\u0001one"}},
		{name: "oversized", profile: profile{Username: strings.Repeat("u", 513)}},
		{name: "invalid UTF-8", profile: profile{Username: string([]byte{0xff})}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			username, organizationName := principalDisplayNames(tt.profile, []organization{{ID: "org-one", Name: "  Company One  "}}, "org-one")
			principal := Principal{
				UserID:           "user-one",
				OrganizationID:   "org-one",
				Username:         username,
				OrganizationName: organizationName,
				ExpiresAt:        time.Now().Add(time.Minute).Unix(),
			}
			ctx := (&Runtime{}).authorizedContext(context.Background(), "session-one", principal)
			assertPrincipalDisplayNamesConsistency(t, ctx, principal)
		})
	}
}

func assertPrincipalDisplayNamesConsistency(t *testing.T, ctx context.Context, principal Principal) {
	t.Helper()
	names, ok := identity.DisplayNamesFromContext(ctx, identity.Member{OrganizationID: principal.OrganizationID, UserID: principal.UserID})
	if principal.Username == "" || principal.OrganizationName == "" {
		if principal.Username != "" || principal.OrganizationName != "" || ok || names != (identity.DisplayNames{}) {
			t.Fatalf("incomplete principal labels %#v with typed labels %#v, %v", principal, names, ok)
		}
		return
	}
	if !ok || names.Username != principal.Username || names.OrganizationName != principal.OrganizationName {
		t.Fatalf("principal labels %#v disagree with typed labels %#v, %v", principal, names, ok)
	}
}

func TestIdentityOnlyRequirePublishesVerifiedDisplayNamesWithoutExtraRequests(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	session := sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
	csrf := session["csrf_token"].(string)
	f.profileNoUsername = true
	observer := observeIdentity(t, a, false)
	beforeProfiles := f.profileRequests.Load()
	hits := 0

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/protected", a.Require(), func(c *gin.Context) {
		principal, ok := FromContext(c.Request.Context())
		if !ok || principal.UserID != "user-one" || principal.OrganizationID != "org-one" || principal.Username != "Synthetic member" || principal.OrganizationName != "Company One" {
			t.Errorf("principal = %#v, %v", principal, ok)
		}
		names, ok := identity.DisplayNamesFromContext(c.Request.Context(), identity.Member{OrganizationID: "org-one", UserID: "user-one"})
		if !ok || names.Username != "Synthetic member" || names.OrganizationName != "Company One" {
			t.Errorf("display names = %#v, %v", names, ok)
		}
		if _, ok := identity.AuthorizationFromContext(c.Request.Context()); ok {
			t.Error("display names created authorization")
		}
		assertPrincipalDisplayNamesConsistency(t, c.Request.Context(), principal)
		hits++
		c.Status(http.StatusNoContent)
	})

	request := func(csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "http://localhost:5180/protected", nil)
		r.AddCookie(cookie)
		r.Header.Set("Origin", a.config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("X-Organization-ID", "org-one")
		r.Header.Set("X-Organization-Revision", "1")
		r.Header.Set("X-Username", "forged-user")
		r.Header.Set("X-Organization-Name", "Forged Company")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}

	if response := request("wrong-csrf"); response.Code != http.StatusForbidden || hits != 0 {
		t.Fatalf("invalid CSRF HTTP %d hits=%d", response.Code, hits)
	}
	if len(observer.paths) != 0 || f.profileRequests.Load() != beforeProfiles {
		t.Fatal("CSRF rejection contacted the identity authority")
	}
	if response := request(csrf); response.Code != http.StatusNoContent || hits != 1 {
		t.Fatalf("verified request HTTP %d hits=%d", response.Code, hits)
	}
	if observer.paths["/api/my-account/organization-identity"] != 1 || len(observer.paths) != 1 || f.profileRequests.Load() != beforeProfiles+1 {
		t.Fatalf("display forwarding changed authority calls: paths=%v profiles=%d->%d", observer.paths, beforeProfiles, f.profileRequests.Load())
	}

	f.denied = true
	if response := request(csrf); response.Code != http.StatusForbidden || hits != 1 {
		t.Fatalf("revoked request HTTP %d hits=%d", response.Code, hits)
	}
}

func TestIdentityOnlyRequireAllowsMissingDisplayNames(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	f.profileSubOnly = true
	session := sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
	csrf := session["csrf_token"].(string)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/protected", a.Require(), func(c *gin.Context) {
		principal, ok := FromContext(c.Request.Context())
		if !ok || principal.UserID != "user-one" || principal.OrganizationID != "org-one" || principal.Username != "" || principal.OrganizationName != "" {
			t.Errorf("principal = %#v, %v", principal, ok)
		}
		assertPrincipalDisplayNamesConsistency(t, c.Request.Context(), principal)
		c.Status(http.StatusNoContent)
	})
	r := httptest.NewRequest(http.MethodPost, "http://localhost:5180/protected", nil)
	r.AddCookie(cookie)
	r.Header.Set("Origin", a.config.Origin)
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("X-Organization-ID", "org-one")
	r.Header.Set("X-Organization-Revision", "1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("missing display names changed admission: HTTP %d", w.Code)
	}
}

func TestIdentityOnlyRequireOmitsInvalidDisplayNamesWithoutDenyingPrincipal(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	invalid := "user\u0001one"
	f.profileUsername = &invalid
	cookie := loginFixture(t, a, f)
	session := sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
	csrf := session["csrf_token"].(string)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/protected", a.Require(), func(c *gin.Context) {
		principal, ok := FromContext(c.Request.Context())
		if !ok || principal.Username != "" || principal.OrganizationName != "" {
			t.Errorf("principal = %#v, %v", principal, ok)
		}
		assertPrincipalDisplayNamesConsistency(t, c.Request.Context(), principal)
		c.Status(http.StatusNoContent)
	})
	r := httptest.NewRequest(http.MethodPost, "http://localhost:5180/protected", nil)
	r.AddCookie(cookie)
	r.Header.Set("Origin", a.config.Origin)
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("X-Organization-ID", "org-one")
	r.Header.Set("X-Organization-Revision", "1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("invalid labels changed admission: HTTP %d", w.Code)
	}
}

func TestResourceRequireOmitsInvalidDisplayNamesWithoutDenyingPrincipal(t *testing.T) {
	for _, tt := range []struct {
		name     string
		username string
	}{
		{name: "control", username: "user\u0001one"},
		{name: "oversized", username: strings.Repeat("u", 513)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, f := fixtureRuntime(t)
			f.userInfoUsername = &tt.username
			cookie := loginFixture(t, a, f)
			session := sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
			csrf := session["csrf_token"].(string)

			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.POST("/protected", a.Require(), func(c *gin.Context) {
				principal, ok := FromContext(c.Request.Context())
				if !ok || principal.Username != "" || principal.OrganizationName != "" {
					t.Errorf("principal = %#v, %v", principal, ok)
				}
				assertPrincipalDisplayNamesConsistency(t, c.Request.Context(), principal)
				c.Status(http.StatusNoContent)
			})
			r := httptest.NewRequest(http.MethodPost, "http://localhost:5180/protected", nil)
			r.AddCookie(cookie)
			r.Header.Set("Origin", a.config.Origin)
			r.Header.Set("X-CSRF-Token", csrf)
			r.Header.Set("X-Organization-ID", "org-one")
			r.Header.Set("X-Organization-Revision", "1")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			if w.Code != http.StatusNoContent {
				t.Fatalf("invalid labels changed admission: HTTP %d", w.Code)
			}
		})
	}
}
