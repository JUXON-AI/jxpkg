package logtobff

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/identity"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/logto-io/go/v2/client"
)

type globalAuthorityFixture struct {
	decision GlobalAccess
	err      error
}

func (f *globalAuthorityFixture) Permissions(context.Context, string) (GlobalAccess, error) {
	return f.decision, f.err
}
func globalFixture(t *testing.T) (*Runtime, *session, *globalAuthorityFixture, *atomic.Value) {
	t.Helper()
	f, _ := fixtureAuthority(t)
	t.Cleanup(func() {
		if f.userInfoCalls.Load() != 0 {
			t.Error("global mode repeated user info lookup")
		}
	})
	var scope atomic.Value
	scope.Store("credits:read mcphub:read")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			if r.ParseForm() != nil {
				w.WriteHeader(400)
				return
			}
			if r.Form.Get("resource") != "" {
				token := f.signed(jwt.MapClaims{"iss": f.url + "/oidc", "aud": "https://admin.invalid/api", "sub": "user-one", "client_id": "client-one", "scope": scope.Load().(string), "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()})
				w.Header().Set("Content-Type", "application/json")
				if json.NewEncoder(w).Encode(map[string]any{"access_token": token, "refresh_token": "refresh-fixture", "expires_in": 3600, "token_type": "Bearer", "scope": scope.Load().(string)}) != nil {
					t.Error("write fixture token")
				}
				return
			}
		}
		f.ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Close)
	f.url = upstream.URL
	store, e := newStore("127.0.0.1:1", "", base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "global-test:")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if store.db.Close() != nil {
			t.Error("close fixture store")
		}
	})
	authority := &globalAuthorityFixture{decision: GlobalAccess{Allowed: true, Permissions: []string{"credits:read", "identity:read"}, Username: "admin-one", Name: "Synthetic admin", Avatar: "https://avatar.invalid/one.png"}}
	runtime := &Runtime{config: Config{Endpoint: upstream.URL, Origin: "http://localhost:5190", ClientID: "client-one", ClientSecret: "fixture-secret", APIResource: "https://admin.invalid/api", Scopes: []string{"openid", "profile", "offline_access", "credits:read", "mcphub:read"}}, http: upstream.Client(), keys: oidc.NewRemoteKeySet(context.Background(), upstream.URL+"/oidc/jwks"), store: store, globalAuthority: authority}
	now := time.Now()
	value := &session{Subject: "user-one", SDK: map[string]string{client.StorageKeyRefreshToken: "refresh-fixture", client.StorageKeyIdToken: f.signed(jwt.MapClaims{"sub": "user-one", "aud": "client-one", "iss": upstream.URL + "/oidc", "exp": now.Add(time.Hour).Unix()})}, CSRF: "synthetic-csrf", PolicyVersion: sessionPolicyVersion, AuthenticatedAt: now, IdleUntil: now.Add(time.Minute), AbsoluteUntil: now.Add(sessionAbsoluteLifetime), Until: now.Add(time.Minute)}
	return runtime, value, authority, &scope
}
func TestGlobalDecisionSeparatesAllowlistAndPermissions(t *testing.T) {
	a, s, authority, _ := globalFixture(t)
	data, p, e := a.globalSnapshot(context.Background(), s)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Join(p.Permissions, " ") != "credits:read" || data["authenticated"] != true {
		t.Fatal("permission intersection incorrect")
	}
	if user := data["user"].(profile); user.Name != "Synthetic admin" || user.Username != "admin-one" || user.Subject != "user-one" || user.Avatar != "https://avatar.invalid/one.png" {
		t.Fatal("display metadata source changed")
	}
	authority.decision = GlobalAccess{Allowed: true}
	if _, p, e = a.globalSnapshot(context.Background(), s); e != nil || len(p.Permissions) != 0 {
		t.Fatal("allowlisted user without roles denied")
	}
	authority.decision = GlobalAccess{}
	if _, _, e = a.globalSnapshot(context.Background(), s); classify(e).status != 403 {
		t.Fatal("zero decision admitted")
	}
	authority.err = ErrUnavailable
	if _, _, e = a.globalSnapshot(context.Background(), s); classify(e).status != 503 {
		t.Fatal("outage treated as deny or allow")
	}
	authority.err = ErrGlobalAccessDenied
	if _, _, e = a.globalSnapshot(context.Background(), s); classify(e).status != 403 {
		t.Fatal("explicit deny ignored")
	}
}

func TestGlobalAvatarOmitsInvalidDisplayURLs(t *testing.T) {
	for _, value := range []string{"", "/one.png", "http://avatar.invalid/one.png", "data:image/png;base64,x", "https://user@avatar.invalid/a", "https:///one.png", "https://avatar.invalid/\n", "https://avatar.invalid/" + strings.Repeat("a", 4096)} {
		if globalAvatar(value) != "" {
			t.Fatal("invalid avatar accepted")
		}
	}
}

func TestGlobalDisplayMetadataIsBounded(t *testing.T) {
	for _, value := range []string{strings.Repeat("a", 513), "user\x00name", "name\nvalue", string([]byte{0xff})} {
		if globalDisplayName(value) != "" {
			t.Fatal("unbounded display metadata accepted")
		}
	}
	if globalDisplayName("  史可凡  ") != "史可凡" {
		t.Fatal("valid name omitted")
	}
}
func TestGlobalRefreshesResourceScope(t *testing.T) {
	a, s, _, scope := globalFixture(t)
	_, p, e := a.globalSnapshot(context.Background(), s)
	if e != nil || len(p.Permissions) != 1 {
		t.Fatal("initial authority", e)
	}
	scope.Store("mcphub:read")
	_, p, e = a.globalSnapshot(context.Background(), s)
	if e != nil || len(p.Permissions) != 0 {
		t.Fatal("cached scope survived revocation", e)
	}
}
func TestGlobalContextNeverPublishesEmployeeCapabilities(t *testing.T) {
	a, _, _, _ := globalFixture(t)
	p := Principal{UserID: "user-one", Username: "User", OrganizationRevision: "epoch", Permissions: []string{"credits:read"}, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	ctx := a.authorizedContext(context.Background(), "opaque-session", p)
	global, ok := GlobalFromContext(ctx)
	if !ok || global.UserID != p.UserID {
		t.Fatal("global context absent")
	}
	global.Permissions[0] = "changed"
	again, _ := GlobalFromContext(ctx)
	if again.Permissions[0] != "credits:read" {
		t.Fatal("mutable permissions")
	}
	if _, ok := FromContext(ctx); ok {
		t.Fatal("employee principal leaked")
	}
	if _, ok := identity.AuthorizationFromContext(ctx); ok {
		t.Fatal("employee capability leaked")
	}
	if !errors.Is(Revalidate(ctx), ErrAuthorizationChanged) {
		t.Fatal("employee revalidation leaked")
	}
	expired := context.WithValue(context.Background(), globalPrincipalKey{}, GlobalPrincipal{UserID: "user-one", Epoch: "x", ExpiresAt: 1})
	if _, ok := GlobalFromContext(expired); ok {
		t.Fatal("expired principal")
	}
}
func TestGlobalRenewalBindsCSRFAndEpoch(t *testing.T) {
	a, s, _, _ := globalFixture(t)
	_, p, e := a.globalSnapshot(context.Background(), s)
	if e != nil {
		t.Fatal(e)
	}
	request := httptest.NewRequest("POST", "http://localhost:5190/auth/session", nil)
	request.Header.Set("Origin", a.config.Origin)
	request.Header.Set("X-CSRF-Token", s.CSRF)
	request.Header.Set("X-Authority-Epoch", p.OrganizationRevision)
	previous := s.IdleUntil
	result := a.renewGlobalSession(request, s)
	if result.status != 200 || !s.IdleUntil.After(previous) || result.data.(map[string]any)["expires_at"].(int64) <= previous.Unix() {
		t.Fatal("renewal expiry not extended")
	}
	request.Header.Set("X-Authority-Epoch", "old")
	if a.renewGlobalSession(request, s).status != 409 {
		t.Fatal("stale authority accepted")
	}
	request.Header.Del("X-CSRF-Token")
	if a.renewGlobalSession(request, s).status != 403 {
		t.Fatal("CSRF absent accepted")
	}
}
func TestGlobalModeCryptographicIsolationAndRoutes(t *testing.T) {
	a, _, _, _ := globalFixture(t)
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	employee, e := newStore("127.0.0.1:1", "", key, "product:")
	if e != nil {
		t.Fatal(e)
	}
	defer employee.db.Close()
	global, e := newStore("127.0.0.1:1", "", key, "product:global:")
	if e != nil {
		t.Fatal(e)
	}
	defer global.db.Close()
	sealed, e := employee.seal(employee.prefix+"session:one", map[string]string{"subject": "user-one"})
	if e != nil {
		t.Fatal(e)
	}
	var value any
	if global.open(global.prefix+"session:one", sealed, &value) == nil {
		t.Fatal("cross-mode session decrypted")
	}
	for _, path := range []string{"/auth/switch-organization", "/auth/account-center"} {
		r := httptest.NewRequest("POST", "http://localhost:5190"+path, nil)
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatalf("organization route %s exposed: %d", path, w.Code)
		}
	}
	if _, e := NewGlobal(context.Background(), Config{}, nil); e == nil {
		t.Fatal("nil authority admitted")
	}
	cfg := a.config
	cfg.Scopes = append(cfg.Scopes, "urn:logto:scope:organizations")
	if _, e := NewGlobal(context.Background(), cfg, a.globalAuthority); e == nil {
		t.Fatal("organization scope admitted")
	}
}
