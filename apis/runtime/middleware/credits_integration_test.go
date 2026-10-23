package middleware_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	browsercredits "github.com/JUXON-AI/jxpkg/apis/credits"
	"github.com/JUXON-AI/jxpkg/apis/runtime/logtobff"
	"github.com/JUXON-AI/jxpkg/apis/runtime/middleware"
	"github.com/JUXON-AI/jxpkg/apis/runtime/server"
	"github.com/JUXON-AI/jxpkg/credits"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type integrationTransport func(*http.Request) (*http.Response, error)

func (f integrationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// This authority runs only on a disposable loopback server; it models identity-only login,
// leaving the real SDK, signature verification, Redis, CSRF and router chain in place.
type creditsAuthority struct {
	key             *rsa.PrivateKey
	endpoint, nonce string
	status          atomic.Int32
}

func (a *creditsAuthority) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if status := a.status.Load(); status != 0 {
		w.WriteHeader(int(status))
		code := "access_denied"
		if status == http.StatusServiceUnavailable {
			code = "temporarily_unavailable"
		}
		if err := json.NewEncoder(w).Encode(map[string]string{"error": code}); err != nil {
			return
		}
		return
	}
	var body any
	switch r.URL.Path {
	case "/oidc/.well-known/openid-configuration":
		body = map[string]any{"issuer": a.endpoint + "/oidc", "authorization_endpoint": a.endpoint + "/oidc/auth", "token_endpoint": a.endpoint + "/oidc/token", "jwks_uri": a.endpoint + "/oidc/jwks", "userinfo_endpoint": a.endpoint + "/oidc/me", "end_session_endpoint": a.endpoint + "/oidc/session/end", "revocation_endpoint": a.endpoint + "/oidc/revoke", "id_token_signing_alg_values_supported": []string{"RS256"}}
	case "/oidc/jwks":
		body = map[string]any{"keys": []map[string]any{{"kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(a.key.N.Bytes()), "e": "AQAB"}}}
	case "/oidc/token":
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": a.endpoint + "/oidc", "aud": "credits-integration", "sub": "user-one", "nonce": a.nonce, "organization_id": "org-one", "organization_identity_revision": "1", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()})
		token.Header["kid"] = "test"
		signed, err := token.SignedString(a.key)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		body = map[string]any{"access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "id_token": signed, "expires_in": 300, "scope": "profile urn:logto:scope:organizations", "token_type": "Bearer"}
	case "/oidc/me":
		body = map[string]any{"sub": "user-one", "organizations": []string{"org-one"}}
	case "/api/my-account/organization-identity":
		body = map[string]any{"organization_id": "org-one", "revision": "1", "organizations": []map[string]string{{"id": "org-one", "name": "Synthetic company"}}}
	default:
		w.WriteHeader(404)
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		return
	}
}

func TestLogtoCreditsExecutionAndBalanceIntegration(t *testing.T) {
	file := os.Getenv("LOGTO_BFF_TEST_CONFIG_FILE")
	if file == "" {
		t.Skip("requires explicitly configured disposable Redis")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal("test configuration unavailable")
	}
	var cfg struct {
		RedisAddress  string `json:"redisAddress"`
		RedisPassword string `json:"redisPassword"`
	}
	if json.Unmarshal(raw, &cfg) != nil || cfg.RedisAddress == "" {
		t.Fatal("test configuration requires disposable Redis address")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	authority := &creditsAuthority{key: key}
	upstream := httptest.NewServer(authority)
	authority.endpoint = upstream.URL
	t.Cleanup(upstream.Close)
	var entropy [32]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	secret := base64.RawURLEncoding.EncodeToString(entropy[:])
	bff, err := logtobff.New(context.Background(), logtobff.Config{Endpoint: upstream.URL, Origin: "http://localhost:5180", ClientID: "credits-integration", ClientSecret: "synthetic-client-secret", Scopes: []string{"profile"}, CookieName: "credits_integration", Namespace: "integration-" + secret[:12], RedisAddress: cfg.RedisAddress, RedisPassword: cfg.RedisPassword, SessionKey: secret, Environment: "local", AllowLocalHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bff.Close(); err != nil {
			t.Error("BFF close failed")
		}
	})
	callAuth := func(path string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "http://localhost:5180"+path, nil)
		r.RequestURI = r.URL.RequestURI()
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		bff.Handler().ServeHTTP(w, r)
		return w
	}
	start := callAuth("/auth/login", nil)
	if start.Code != 302 || len(start.Result().Cookies()) == 0 {
		t.Fatal("login transaction unavailable")
	}
	target, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal("invalid authorization redirect")
	}
	authority.nonce = target.Query().Get("nonce")
	callback := callAuth("/auth/callback?code=synthetic-code&state="+url.QueryEscape(target.Query().Get("state")), start.Result().Cookies()[0])
	if callback.Code != 302 {
		t.Fatal("SDK callback failed")
	}
	var cookie *http.Cookie
	for _, c := range callback.Result().Cookies() {
		if c.Name == "credits_integration" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("missing business session cookie")
	}
	session := callAuth("/auth/session", cookie)
	var info struct {
		CSRF string `json:"csrf_token"`
	}
	if session.Code != 200 || json.Unmarshal(session.Body.Bytes(), &info) != nil || info.CSRF == "" {
		t.Fatal("session unavailable")
	}
	calls := 0
	client, err := credits.NewClientWithTransport(credits.Config{Endpoint: "https://credits.invalid"}, integrationTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		var subject credits.Subject
		if err := json.NewDecoder(r.Body).Decode(&subject); err != nil || subject != (credits.Subject{OrganizationID: "org-one", UserID: "user-one"}) {
			t.Error("unverified identity reached credits")
		}
		body := `{"base_url":"https://models.invalid/v1","api_key":"synthetic-key"}`
		if r.URL.Path == credits.BalancePath {
			body = `{"state":"ready","quota":6500,"used_quota":3500}`
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	router := server.NewRouter("/v1/")
	if err := browsercredits.RegisterBrowserBalance(router, "jxagent", client, bff); err != nil {
		t.Fatal(err)
	}
	router.GinEngine().POST("/model", bff.Require(), middleware.BindCreditsExecution(client), func(c *gin.Context) {
		for range 2 {
			connection, err := credits.ConnectionFromContext(c.Request.Context())
			if err != nil || connection.APIKey != "synthetic-key" {
				t.Error("verified model acquisition failed")
			}
		}
		c.Status(204)
	})
	request := func(path, organization, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "http://localhost:5180"+path, strings.NewReader(`{"request":{"organization_id":"forged","user_id":"forged"}}`))
		r.AddCookie(cookie)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://localhost:5180")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("X-Organization-ID", organization)
		r.Header.Set("X-Organization-Revision", "1")
		w := httptest.NewRecorder()
		router.GinEngine().ServeHTTP(w, r)
		return w
	}
	if w := request("/model", "org-one", info.CSRF); w.Code != 204 || calls != 1 {
		t.Fatalf("model status=%d calls=%d", w.Code, calls)
	}
	balance := request("/v1/jxagent.GetMyModelBalance", "org-one", info.CSRF)
	var result browsercredits.GetMyModelBalanceResponse
	if balance.Code != 200 || json.Unmarshal(balance.Body.Bytes(), &result) != nil || result.Code != 0 || result.Response.Quota != 6500 || result.Response.UserID != "user-one" || result.Response.OrganizationID != "org-one" || calls != 2 {
		t.Fatal("verified balance response lost membership or wallet")
	}
	for _, tc := range []struct {
		name, org, csrf string
		status          int
	}{{"changed_organization", "org-other", info.CSRF, 409}, {"invalid_csrf", "org-one", "invalid", 403}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := request("/model", tc.org, tc.csrf); got.Code != tc.status || calls != 2 {
				t.Fatal("invalid browser context reached credits")
			}
		})
	}
	for _, status := range []int{503, 403} {
		authority.status.Store(int32(status))
		if got := request("/model", "org-one", info.CSRF); got.Code != status || calls != 2 {
			t.Fatalf("authority failure %d reached credits", status)
		}
		authority.status.Store(0)
		recovered := callAuth("/auth/session", cookie)
		if recovered.Code != 200 || json.Unmarshal(recovered.Body.Bytes(), &info) != nil {
			t.Fatal("session did not recover after identity authority returned")
		}
		for _, next := range recovered.Result().Cookies() {
			if next.Name == cookie.Name {
				cookie = next
			}
		}
	}
}
