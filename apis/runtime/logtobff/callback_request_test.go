package logtobff

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestCallbackRestoresRequestURIForSDKAfterLogRedaction(t *testing.T) {
	f, _ := fixtureAuthority(t)
	var authorizationCodeExchanges atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" && r.ParseForm() == nil && r.Form.Get("grant_type") == "authorization_code" {
			authorizationCodeExchanges.Add(1)
		}
		f.ServeHTTP(w, r)
	}))
	f.url = upstream.URL
	t.Cleanup(upstream.Close)
	a := fixtureRuntimeWithAuthority(t, upstream.URL, loadFixtureRedisConfig(t), "mcphub_test")
	t.Logf("redis namespace=%s", a.config.Namespace)

	start := callAuth(a, "GET", "/auth/login", "", nil, "")
	if start.Code != http.StatusFound {
		t.Fatalf("login HTTP %d", start.Code)
	}
	target, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal("redirect invalid")
	}
	f.nonce = target.Query().Get("nonce")
	callbackPath := "/auth/callback?code=fixture-code&state=" + url.QueryEscape(target.Query().Get("state"))
	tx := start.Result().Cookies()[0]

	// SameOrigin retains URL.RawQuery for protocol handlers but redacts
	// RequestURI before shared access logging.
	callback := httptest.NewRequest(http.MethodGet, "http://localhost:5180"+callbackPath, nil)
	callback.RequestURI = callback.URL.EscapedPath()
	callback.AddCookie(tx)
	response := httptest.NewRecorder()
	a.Handler().ServeHTTP(response, callback)
	if response.Code != http.StatusFound {
		t.Fatalf("callback HTTP %d %s", response.Code, response.Body.String())
	}
	if callback.RequestURI != "/auth/callback" {
		t.Fatalf("callback RequestURI mutated: %q", callback.RequestURI)
	}
	if exchanges := authorizationCodeExchanges.Load(); exchanges != 1 {
		t.Fatalf("authorization code exchanged %d times", exchanges)
	}

	var session *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == a.config.CookieName {
			session = cookie
			break
		}
	}
	if session == nil {
		t.Fatal("session cookie absent")
	}
	body := sessionBody(t, callAuth(a, "GET", "/auth/session", "", session, ""))
	if body["authenticated"] != true || body["organization_id"] != "org-one" {
		t.Fatal("callback did not establish an authenticated session")
	}

	replay := httptest.NewRequest(http.MethodGet, "http://localhost:5180"+callbackPath, nil)
	replay.RequestURI = replay.URL.EscapedPath()
	replay.AddCookie(tx)
	replayResponse := httptest.NewRecorder()
	a.Handler().ServeHTTP(replayResponse, replay)
	if replayResponse.Code != http.StatusBadRequest {
		t.Fatalf("callback replay HTTP %d", replayResponse.Code)
	}
}
