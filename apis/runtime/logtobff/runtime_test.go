package logtobff

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

func TestConfigurationFailsClosed(t *testing.T) {
	for _, origin := range []string{"http://192.168.16.48:5180", "http://evil.invalid", "http://localhost:5180/", "https://user:secret@example.invalid"} {
		if validOrigin(origin, true) {
			t.Fatalf("accepted invalid local origin")
		}
	}
	if !validOrigin("http://localhost:5180", true) || validOrigin("http://localhost:5180", false) {
		t.Fatal("local HTTP boundary")
	}
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("published anonymous principal")
	}
	if Revalidate(context.Background()) != ErrAuthorizationChanged {
		t.Fatal("missing revalidation allowed")
	}
}

type fakeAuthority struct {
	key                            *rsa.PrivateKey
	url, nonce                     string
	denied, unavailable, readOnly  bool
	userInvalid, clientInvalid     bool
	nativeSessionConsumed          bool
	logoutCommitLost, logoutBlock  bool
	logoutStatus                   int
	logoutCalls                    int
	logoutMethod, logoutPath       string
	logoutAuthorization            string
	logoutBody, logoutResponseBody string
	revokeCalls, endSessionCalls   int
	resourceRevokeCalls            int
	resourceRevokeStatus           int
	resourceRevokeAuthorization    string
	resourceRevokeBody             string
	resourceRevokeRequestID        string
	refreshes                      int
	organization, revision         string
}

func (f *fakeAuthority) signed(claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "fixture-key"
	value, err := token.SignedString(f.key)
	if err != nil {
		panic(err)
	}
	return value
}
func (f *fakeAuthority) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if f.unavailable {
		w.WriteHeader(503)
		if _, err := fmt.Fprint(w, `{"error":"temporarily_unavailable"}`); err != nil {
			return
		}
		return
	}
	switch r.URL.Path {
	case "/oidc/.well-known/openid-configuration":
		if err := json.NewEncoder(w).Encode(map[string]any{"issuer": f.url + "/oidc", "authorization_endpoint": f.url + "/oidc/auth", "token_endpoint": f.url + "/oidc/token", "jwks_uri": f.url + "/oidc/jwks", "userinfo_endpoint": f.url + "/oidc/me", "end_session_endpoint": f.url + "/oidc/session/end", "revocation_endpoint": f.url + "/oidc/revoke", "id_token_signing_alg_values_supported": []string{"RS256"}}); err != nil {
			return
		}
	case "/oidc/jwks":
		if err := json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "RSA", "kid": "fixture-key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()), "e": "AQAB"}}}); err != nil {
			return
		}
	case "/oidc/token":
		if f.clientInvalid {
			w.WriteHeader(401)
			if _, err := fmt.Fprint(w, `{"error":"invalid_client"}`); err != nil {
				return
			}
			return
		}
		if r.ParseForm() != nil {
			w.WriteHeader(400)
			return
		}
		org := r.Form.Get("organization_id")
		if f.denied && org != "" {
			w.WriteHeader(403)
			if _, err := fmt.Fprint(w, `{"error":"access_denied"}`); err != nil {
				return
			}
			return
		}
		f.refreshes++
		scopes := "read:credits manage:credits"
		if f.readOnly {
			scopes = "read:credits"
		}
		access := "opaque-account-access"
		if org != "" {
			access = f.signed(jwt.MapClaims{"iss": f.url + "/oidc", "aud": "https://credits.invalid/api", "sub": "user-one", "client_id": "client-one", "organization_id": org, "scope": scopes, "exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix()})
		}
		response := map[string]any{"access_token": access, "refresh_token": fmt.Sprintf("refresh-%d", f.refreshes), "expires_in": 300, "scope": scopes, "token_type": "Bearer"}
		if r.Form.Get("grant_type") == "authorization_code" {
			response["id_token"] = f.signed(jwt.MapClaims{"iss": f.url + "/oidc", "aud": "client-one", "sub": "user-one", "nonce": f.nonce, "organization_id": f.organization, "organization_identity_revision": f.revision, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()})
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			return
		}
	case "/oidc/me":
		if f.userInvalid {
			w.WriteHeader(401)
			if _, err := fmt.Fprint(w, `{"error":"invalid_token"}`); err != nil {
				return
			}
			return
		}
		if r.Header.Get("Authorization") != "Bearer opaque-account-access" {
			w.WriteHeader(401)
			return
		}
		if _, err := fmt.Fprint(w, `{"sub":"user-one","name":"Synthetic member","organizations":["org-one","org-forbidden"]}`); err != nil {
			return
		}
	case "/api/my-account/organization-identity":
		if f.userInvalid || f.nativeSessionConsumed {
			w.WriteHeader(401)
			if _, err := fmt.Fprint(w, `{"error":"invalid_token"}`); err != nil {
				return
			}
			return
		}
		if f.denied {
			w.WriteHeader(403)
			if _, err := fmt.Fprint(w, `{"error":"access_denied"}`); err != nil {
				return
			}
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"organization_id": f.organization, "revision": f.revision, "organizations": []organization{{ID: "org-one", Name: "Company One"}, {ID: "org-two", Name: "Company Two"}}}); err != nil {
			return
		}
	case "/api/my-account/browser-session/logout":
		f.logoutCalls++
		f.logoutMethod = r.Method
		f.logoutPath = r.URL.Path
		f.logoutAuthorization = r.Header.Get("Authorization")
		body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
		if err != nil {
			http.Error(w, "invalid logout request", http.StatusBadRequest)
			return
		}
		f.logoutBody = string(body)
		if f.logoutBlock {
			<-r.Context().Done()
			return
		}
		if f.logoutCommitLost {
			f.nativeSessionConsumed = true
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "connection unavailable", http.StatusInternalServerError)
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				http.Error(w, "connection unavailable", http.StatusInternalServerError)
				return
			}
			if err = conn.Close(); err != nil {
				return
			}
			return
		}
		if f.logoutStatus != http.StatusNoContent {
			if f.logoutStatus >= http.StatusMultipleChoices && f.logoutStatus < http.StatusBadRequest {
				w.Header().Set("Location", f.url+"/oidc/session/end")
			}
			w.WriteHeader(f.logoutStatus)
			if _, err := fmt.Fprint(w, f.logoutResponseBody); err != nil {
				return
			}
			return
		}
		f.nativeSessionConsumed = true
		w.WriteHeader(http.StatusNoContent)
	case "/api/my-account/resource-grants/revoke":
		f.resourceRevokeCalls++
		f.resourceRevokeAuthorization = r.Header.Get("Authorization")
		f.resourceRevokeRequestID = r.Header.Get("X-Request-ID")
		body, err := io.ReadAll(io.LimitReader(r.Body, (4<<10)+1))
		if err != nil || len(body) > 4<<10 {
			http.Error(w, "invalid revoke request", http.StatusBadRequest)
			return
		}
		f.resourceRevokeBody = string(body)
		status := f.resourceRevokeStatus
		if status == 0 {
			status = http.StatusNoContent
		}
		if status >= http.StatusMultipleChoices && status < http.StatusBadRequest {
			w.Header().Set("Location", f.url+"/oidc/session/end")
		}
		w.WriteHeader(status)
	case "/oidc/revoke":
		f.revokeCalls++
		if _, err := fmt.Fprint(w, `{}`); err != nil {
			return
		}
	case "/oidc/session/end":
		f.endSessionCalls++
		if _, err := fmt.Fprint(w, `{}`); err != nil {
			return
		}
	default:
		w.WriteHeader(404)
	}
}
func fixtureRuntime(t *testing.T, resource ...string) (*Runtime, *fakeAuthority) {
	t.Helper()
	var (
		private        = loadFixtureRedisConfig(t)
		f, upstreamURL = fixtureAuthority(t)
	)
	return fixtureRuntimeWithAuthority(t, upstreamURL, private, "mcphub_test", resource...), f
}

type fixtureRedis struct {
	Password string
	Address  string
}

func loadFixtureRedisConfig(t *testing.T) fixtureRedis {
	t.Helper()
	file := os.Getenv("LOGTO_BFF_TEST_CONFIG_FILE")
	if file == "" {
		t.Skip("requires explicit local disposable Redis configuration")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal("test config unavailable")
	}
	var private struct {
		RedisPassword string `json:"redisPassword"`
		RedisAddress  string `json:"redisAddress"`
	}
	if json.Unmarshal(data, &private) != nil {
		t.Fatal("test config invalid")
	}
	if private.RedisAddress == "" {
		private.RedisAddress = "127.0.0.1:56379"
	}
	return fixtureRedis{Password: private.RedisPassword, Address: private.RedisAddress}
}

func fixtureAuthority(t *testing.T) (*fakeAuthority, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var (
		f        = &fakeAuthority{key: key, organization: "org-one", revision: "1", logoutStatus: http.StatusNoContent}
		upstream = httptest.NewServer(f)
	)
	f.url = upstream.URL
	t.Cleanup(upstream.Close)
	return f, upstream.URL
}

func fixtureRuntimeWithAuthority(t *testing.T, endpoint string, private fixtureRedis, cookieName string, resource ...string) *Runtime {
	t.Helper()
	apiResource := "https://credits.invalid/api"
	if len(resource) == 1 {
		apiResource = resource[0]
	}
	scopes := []string{"read:credits", "manage:credits"}
	if apiResource == "" {
		scopes = []string{"profile"}
	}
	runtime, err := New(context.Background(), Config{Endpoint: endpoint, Origin: "http://localhost:5180", ClientID: "client-one", ClientSecret: "fixture-secret", APIResource: apiResource, Scopes: scopes, CookieName: cookieName, Namespace: "test-" + testOpaque(t)[:12], RedisAddress: private.Address, RedisPassword: private.Password, SessionKey: testOpaque(t), Environment: "local", AllowLocalHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if runtime.Close() != nil {
			t.Error("redis close failed")
		}
	})
	return runtime
}
func callAuth(a *Runtime, method, path string, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://localhost:5180"+path, strings.NewReader(body))
	r.RequestURI = r.URL.RequestURI()
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if method == "POST" {
		r.Header.Set("Origin", "http://localhost:5180")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("X-Organization-ID", "org-one")
		r.Header.Set("X-Organization-Revision", "1")
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}
func loginFixture(t *testing.T, a *Runtime, f *fakeAuthority) *http.Cookie {
	t.Helper()
	start := callAuth(a, "GET", "/auth/login", "", nil, "")
	if start.Code != 302 {
		t.Fatalf("login HTTP %d", start.Code)
	}
	target, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal("redirect invalid")
	}
	f.nonce = target.Query().Get("nonce")
	callback := "/auth/callback?code=fixture-code&state=" + url.QueryEscape(target.Query().Get("state"))
	tx := start.Result().Cookies()[0]
	response := callAuth(a, "GET", callback, "", tx, "")
	if response.Code != 302 {
		t.Fatalf("SDK callback failed HTTP %d %s", response.Code, response.Body.String())
	}
	replay := callAuth(a, "GET", callback, "", tx, "")
	if replay.Code != 400 {
		t.Fatal("callback replay accepted")
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == a.config.CookieName {
			return cookie
		}
	}
	t.Fatal("session absent")
	return nil
}
func sessionBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if json.Unmarshal(w.Body.Bytes(), &body) != nil {
		t.Fatalf("invalid response status %d", w.Code)
	}
	return body
}
func TestSDKLoginSelectionRevocationAndLogout(t *testing.T) {
	a, f := fixtureRuntime(t)
	cookie := loginFixture(t, a, f)
	session := sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
	if session["organization_id"] != "org-one" || session["organization_revision"] != "1" || session["user"] == nil {
		t.Fatal("callback did not establish selected identity")
	}
	csrf := session["csrf_token"].(string)
	if callAuth(a, "POST", "/auth/organization", `{}`, cookie, csrf).Code != 404 {
		t.Fatal("business selection endpoint still exists")
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	hits := 0
	router.POST("/protected", a.Require("manage:credits"), func(c *gin.Context) {
		p, ok := FromContext(c.Request.Context())
		if !ok || p.UserID != "user-one" || p.OrganizationID != "org-one" {
			t.Error("wrong principal")
		}
		hits++
		c.Status(204)
	})
	protected := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://localhost:5180/protected", nil)
		r.AddCookie(cookie)
		r.Header.Set("Origin", a.config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("X-Organization-ID", "org-one")
		r.Header.Set("X-Organization-Revision", "1")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if protected().Code != 204 || hits != 1 {
		t.Fatal("verified request denied")
	}
	f.readOnly = true
	if protected().Code != 403 || hits != 1 {
		t.Fatal("revoked scope accepted cached token")
	}
	f.denied = true
	if protected().Code != 403 || hits != 1 {
		t.Fatal("removed organization remained valid")
	}
	f.denied = false
	f.readOnly = false
	out := callAuth(a, "POST", "/auth/logout", `{}`, cookie, csrf)
	if out.Code != 200 {
		t.Fatalf("logout HTTP %d", out.Code)
	}
	if callAuth(a, "GET", "/auth/session", "", cookie, "").Code != 401 {
		t.Fatal("logout kept session")
	}
}
func TestSDKDependencyFailureDoesNotExposeProfile(t *testing.T) {
	a, f := fixtureRuntime(t)
	cookie := loginFixture(t, a, f)
	f.unavailable = true
	if callAuth(a, "GET", "/auth/session", "", cookie, "").Code != 503 {
		t.Fatal("unavailable provider allowed")
	}
	f.unavailable = false
	current := sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
	if current["organization_id"] != "org-one" {
		t.Fatal("central identity did not recover")
	}
}

func testOpaque(t *testing.T) string {
	t.Helper()
	s := store{entropy: rand.Reader}
	v, err := s.opaque()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestUserInfoInvalidatesSessionButClientFailureDoesNot(t *testing.T) {
	a, f := fixtureRuntime(t)
	cookie := loginFixture(t, a, f)
	f.clientInvalid = true
	if callAuth(a, "GET", "/auth/session", "", cookie, "").Code != 503 {
		t.Fatal("client configuration failure classified as user logout")
	}
	f.clientInvalid = false
	if callAuth(a, "GET", "/auth/session", "", cookie, "").Code != 200 {
		t.Fatal("recoverable session lost")
	}
	f.userInvalid = true
	if callAuth(a, "GET", "/auth/session", "", cookie, "").Code != 401 {
		t.Fatal("userinfo invalid session was retained")
	}
	f.userInvalid = false
	if callAuth(a, "GET", "/auth/session", "", cookie, "").Code != 401 {
		t.Fatal("invalid session revived")
	}
}
func TestExpiredAndAmbiguousCapabilities(t *testing.T) {
	a, f := fixtureRuntime(t)
	start := callAuth(a, "GET", "/auth/login", "", nil, "")
	target, _ := url.Parse(start.Header().Get("Location"))
	f.nonce = target.Query().Get("nonce")
	tx := start.Result().Cookies()[0]
	path := "/auth/callback?code=fixture&state=wrong&state=" + url.QueryEscape(target.Query().Get("state"))
	if callAuth(a, "GET", path, "", tx, "").Code != 400 {
		t.Fatal("duplicate state accepted")
	}
	path = "/auth/callback?code=fixture&state=" + url.QueryEscape(target.Query().Get("state"))
	if callAuth(a, "GET", path, "", tx, "").Code != 400 {
		t.Fatal("reused failed transaction accepted")
	}
	cookie := loginFixture(t, a, f)
	value, owner, err := a.store.acquire(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	value.IdleUntil = time.Now().Add(30 * time.Millisecond)
	value.Until = value.IdleUntil
	if err = a.store.commit(context.Background(), cookie.Value, owner, cookie.Value, value, false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if callAuth(a, "GET", "/auth/session", "", cookie, "").Code != 401 {
		t.Fatal("expired session accepted")
	}
}
func TestEntropyFailureRejectsWithoutCookie(t *testing.T) {
	a, _ := fixtureRuntime(t)
	a.store.entropy = strings.NewReader("")
	response := callAuth(a, "GET", "/auth/login", "", nil, "")
	if response.Code != 503 || len(response.Result().Cookies()) != 0 {
		t.Fatal("incomplete entropy issued cookie")
	}
	if _, _, err := a.store.start(context.Background(), transaction{}); err == nil {
		t.Fatal("transaction accepted without entropy")
	}
	if _, err := a.store.create(context.Background(), &session{}, ""); err == nil {
		t.Fatal("session accepted without entropy")
	}
	if _, _, err := a.store.acquire(context.Background(), strings.Repeat("a", 43)); err == nil {
		t.Fatal("lease accepted without entropy")
	}
	if _, err := a.store.seal("key", session{}); err == nil {
		t.Fatal("encrypted value accepted without entropy")
	}
}

func TestSensitiveResultRevalidationAndRedisFailure(t *testing.T) {
	a, f := fixtureRuntime(t)
	cookie := loginFixture(t, a, f)
	current := sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
	csrf := current["csrf_token"].(string)
	router := gin.New()
	var revalidated error
	router.POST("/sensitive", a.Require("manage:credits"), func(c *gin.Context) {
		revalidated = Revalidate(c.Request.Context())
		if revalidated != nil {
			c.Status(403)
			return
		}
		c.Status(204)
	})
	run := func() int {
		r := httptest.NewRequest("POST", "http://localhost:5180/sensitive", nil)
		r.AddCookie(cookie)
		r.Header.Set("Origin", a.config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("X-Organization-ID", "org-one")
		r.Header.Set("X-Organization-Revision", "1")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w.Code
	}
	if run() != 204 || revalidated != nil {
		t.Fatal("valid sensitive result denied")
	}
	// 在鉴权与敏感结果之间撤权，返回明文前的独立检查必须拒绝。
	router = gin.New()
	router.POST("/sensitive", a.Require("manage:credits"), func(c *gin.Context) {
		f.readOnly = true
		revalidated = Revalidate(c.Request.Context())
		if revalidated == nil {
			t.Error("revoked permission released sensitive result")
		}
		c.Status(403)
	})
	if run() != 403 || revalidated != ErrAuthorizationChanged {
		t.Fatal("missing final authorization check")
	}
	f.readOnly = false
	original := a.store.db
	a.store.db = redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 20 * time.Millisecond, MaxRetries: -1})
	defer func() { _ = a.store.db.Close(); a.store.db = original }()
	if callAuth(a, "GET", "/auth/session", "", cookie, "").Code != 503 {
		t.Fatal("unavailable Redis allowed")
	}
}

func TestPrincipalSnapshotCannotMutateAuthorizationContext(t *testing.T) {
	primary := "dept-one"
	original := Principal{UserID: "user-one", OrganizationID: "org-one", ExpiresAt: time.Now().Add(time.Minute).Unix(), Permissions: []string{"manage:credits"}, DepartmentIDs: []string{"dept-one"}, PrimaryDepartmentID: &primary}
	ctx := context.WithValue(context.Background(), principalKey{}, original)
	first, ok := FromContext(ctx)
	if !ok {
		t.Fatal("valid principal missing")
	}
	first.Permissions[0] = "other"
	first.DepartmentIDs[0] = "other"
	*first.PrimaryDepartmentID = "other"
	next, ok := FromContext(ctx)
	if !ok || next.Permissions[0] != "manage:credits" || next.DepartmentIDs[0] != "dept-one" || *next.PrimaryDepartmentID != "dept-one" {
		t.Fatal("caller changed shared authorization state")
	}
	original.ExpiresAt = time.Now().Unix() - 1
	expired, ok := FromContext(context.WithValue(ctx, principalKey{}, original))
	if ok || expired.UserID != "" {
		t.Fatal("expired principal exposed")
	}
}

func TestCentralRevisionRejectsOldTabAndDoesNotRewindSession(t *testing.T) {
	a, f := fixtureRuntime(t)
	cookie := loginFixture(t, a, f)
	current := sessionBody(t, callAuth(a, "GET", "/auth/session", "", cookie, ""))
	csrf := current["csrf_token"].(string)
	hits := 0
	router := gin.New()
	router.POST("/write", a.Require("manage:credits"), func(c *gin.Context) { hits++; c.Status(204) })
	request := func(org, revision string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://localhost:5180/write", nil)
		r.AddCookie(cookie)
		r.Header.Set("Origin", a.config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		if org != "" {
			r.Header.Set("X-Organization-ID", org)
			r.Header.Set("X-Organization-Revision", revision)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if request("", "").Code != 409 || hits != 0 {
		t.Fatal("missing page identity executed business write")
	}
	// Central identity changed away and back. New shared Cookie and CSRF cannot authorize an old page snapshot.
	f.revision = "3"
	response := callAuth(a, "GET", "/auth/session", "", cookie, "")
	if response.Code != 200 || len(response.Result().Cookies()) != 1 {
		t.Fatal("central revision was not adopted")
	}
	old := cookie
	cookie = response.Result().Cookies()[0]
	csrf = sessionBody(t, response)["csrf_token"].(string)
	if old.Value == cookie.Value || callAuth(a, "GET", "/auth/session", "", old, "").Code != 401 {
		t.Fatal("old session survived identity adoption")
	}
	if request("org-one", "1").Code != 409 || hits != 0 {
		t.Fatal("old revision executed in new identity")
	}
	if request("org-two", "3").Code != 409 || hits != 0 {
		t.Fatal("foreign organization executed")
	}
	if request("org-one", "3").Code != 204 || hits != 1 {
		t.Fatal("current identity denied")
	}
	// A sensitive operation holding an old principal must not overwrite an already newer stored session.
	expected := Principal{UserID: "user-one", OrganizationID: "org-one", OrganizationRevision: "1"}
	if a.revalidate(context.Background(), cookie.Value, expected, []string{"manage:credits"}) != ErrAuthorizationChanged {
		t.Fatal("stale principal revalidated")
	}
	value, owner, err := a.store.acquire(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	defer a.store.release(context.Background(), cookie.Value, owner)
	if value.Revision != "3" {
		t.Fatal("stale revalidation rewound the shared session")
	}
}

func TestLoginReturnToCancelAndMissingSignedIdentity(t *testing.T) {
	a, f := fixtureRuntime(t)
	for _, target := range []string{"//foreign.invalid", "https://foreign.invalid", "/\\foreign", "/ok\r\nInjected"} {
		if callAuth(a, "GET", "/auth/login?return_to="+url.QueryEscape(target), "", nil, "").Code != 400 {
			t.Fatal("unsafe return accepted")
		}
	}
	start := callAuth(a, "GET", "/auth/switch-organization?return_to=%2Fcredits%3Fview%3Dkeys%23section", "", nil, "")
	target, _ := url.Parse(start.Header().Get("Location"))
	state := target.Query().Get("state")
	f.nonce = target.Query().Get("nonce")
	if target.Query().Get("organization_identity") != "required" {
		t.Fatal("central identity missing")
	}
	response := callAuth(a, "GET", "/auth/callback?code=fixture&state="+url.QueryEscape(state), "", start.Result().Cookies()[0], "")
	if response.Code != 302 || response.Header().Get("Location") != "http://localhost:5180/credits?view=keys#section" {
		t.Fatal("business return path lost")
	}
	start = callAuth(a, "GET", "/auth/login", "", nil, "")
	target, _ = url.Parse(start.Header().Get("Location"))
	state = target.Query().Get("state")
	cancel := callAuth(a, "GET", "/auth/callback?error=access_denied&state="+url.QueryEscape(state), "", start.Result().Cookies()[0], "")
	if cancel.Code != 302 || cancel.Header().Get("Location") != "http://localhost:5180/login-cancelled" {
		t.Fatal("cancel loop")
	}
	start = callAuth(a, "GET", "/auth/login", "", nil, "")
	target, _ = url.Parse(start.Header().Get("Location"))
	f.nonce = target.Query().Get("nonce")
	f.organization = ""
	rejected := callAuth(a, "GET", "/auth/callback?code=fixture&state="+url.QueryEscape(target.Query().Get("state")), "", start.Result().Cookies()[0], "")
	if rejected.Code != 401 {
		t.Fatal("callback accepted missing signed organization")
	}
}
