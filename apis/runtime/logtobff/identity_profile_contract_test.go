package logtobff

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/logto-io/go/v2/client"
)

func TestIdentityOnlyLegacyProfileExpiryDoesNotIssueUserInfo(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	expireStoredAccessTokenAndAddLegacyProfile(t, a, cookie)
	beforeUserInfo, beforeRefresh := f.userInfoCalls.Load(), f.refreshes
	response := callAuth(a, "GET", "/auth/session", "", cookie, "")
	if response.Code != 200 {
		t.Fatalf("online profile refresh HTTP %d", response.Code)
	}
	if f.userInfoCalls.Load() != beforeUserInfo {
		t.Fatal("legacy profile expiry issued UserInfo")
	}
	if f.refreshes-beforeRefresh != 1 {
		t.Fatalf("token refreshed %d times", f.refreshes-beforeRefresh)
	}
	if body := sessionBody(t, response); body["user"].(map[string]any)["name"] != "Synthetic member" {
		t.Fatal("response did not use the fresh online profile")
	}
}

func TestIdentityOnlyRejectsInvalidOnlineProfiles(t *testing.T) {
	tests := []struct {
		name string
		set  func(*fakeAuthority)
		code int
	}{
		{name: "missing", set: func(f *fakeAuthority) { f.profileMissing = true }, code: 503},
		{name: "subject missing", set: func(f *fakeAuthority) { f.profileSubjectMissing = true }, code: 503},
		{name: "subject mismatch", set: func(f *fakeAuthority) { f.profileSubjectMismatch = true }, code: 401},
		{name: "oversize", set: func(f *fakeAuthority) { f.profileOversize = true }, code: 503},
		{name: "malformed", set: func(f *fakeAuthority) { f.identityMalformed = true }, code: 503},
		{name: "unauthorized", set: func(f *fakeAuthority) { f.identityInvalid = true }, code: 401},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a, f := fixtureRuntime(t, "")
			cookie := loginFixture(t, a, f)
			test.set(f)
			if got := callAuth(a, "GET", "/auth/session", "", cookie, "").Code; got != test.code {
				t.Fatalf("invalid profile HTTP %d, want %d", got, test.code)
			}
			if f.userInfoCalls.Load() != 0 {
				t.Fatal("invalid online profile fell back to UserInfo")
			}
		})
	}
}

func TestIdentityOnlyPublishesSubOnlyProfileWithoutAuthorizationClaims(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	f.profileSubOnly = true
	response := callAuth(a, "GET", "/auth/session", "", cookie, "")
	if response.Code != 200 {
		t.Fatalf("sub-only profile HTTP %d", response.Code)
	}
	body := sessionBody(t, response)
	user := body["user"].(map[string]any)
	if user["sub"] != "user-one" || user["name"] != "" || user["customData"] != nil {
		t.Fatalf("unexpected display projection: %#v", user)
	}
	if roles, ok := body["roles"].([]any); !ok || len(roles) != 0 {
		t.Fatalf("authorization roles escaped the display projection: %#v", body["roles"])
	}
}

func TestIdentityOnlyRevokedMembershipDeniesWithoutUserInfo(t *testing.T) {
	a, f := fixtureRuntime(t, "")
	cookie := loginFixture(t, a, f)
	f.identityOrganizations = []organization{{ID: "org-two", Name: "Company Two"}}
	response := callAuth(a, "GET", "/auth/session", "", cookie, "")
	if response.Code != 403 || sessionBody(t, response)["error"] != "organization_not_enabled_for_app" {
		t.Fatalf("revoked membership HTTP %d body=%s", response.Code, response.Body.String())
	}
	if f.userInfoCalls.Load() != 0 {
		t.Fatal("revoked membership fell back to UserInfo")
	}
}

func expireStoredAccessTokenAndAddLegacyProfile(t *testing.T, a *Runtime, cookie *http.Cookie) {
	t.Helper()
	value, owner, err := a.store.acquire(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	defer a.store.release(context.Background(), cookie.Value, owner)
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
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if json.Unmarshal(data, &raw) != nil {
		t.Fatal("invalid session fixture")
	}
	raw["profile"] = map[string]any{"sub": "user-one", "name": "Legacy cached member"}
	raw["profile_until"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	key := a.store.prefix + "s:" + cookie.Value
	sealed, err := a.store.seal(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := sessionDeadline(value, a.store.nowTime())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.store.db.Set(context.Background(), key, sealed, deadline.Sub(a.store.nowTime())).Err(); err != nil {
		t.Fatal(err)
	}
}
