package logtobff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/JUXON-AI/jxpkg/requestid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

func TestAutoLoginUsesPromptNoneAndKeepsGuestReturnNonAuthoritative(t *testing.T) {
	a, _ := fixtureRuntime(t)

	explicit := callAuth(a, http.MethodGet, "/auth/login?return_to=%2F", "", nil, "")
	explicitTarget, err := url.Parse(explicit.Header().Get("Location"))
	if err != nil || explicitTarget.Query().Get("prompt") != "consent" {
		t.Fatalf("explicit login prompt=%q", explicitTarget.Query().Get("prompt"))
	}

	start := callAuth(a, http.MethodGet, "/auth/auto-login?return_to=%2Fcatalog", "", nil, "")
	if start.Code != http.StatusFound {
		t.Fatalf("auto login HTTP %d %s", start.Code, start.Body.String())
	}
	target, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal("auto login redirect invalid")
	}
	query := target.Query()
	if len(query["prompt"]) != 1 || query.Get("prompt") != "none" {
		t.Fatalf("auto login prompt=%q", query["prompt"])
	}
	if len(query["state"]) != 1 || query.Get("state") == "" ||
		len(query["code_challenge"]) != 1 || query.Get("code_challenge") == "" ||
		query.Get("code_challenge_method") != "S256" ||
		len(query["nonce"]) != 1 || len(query.Get("nonce")) < 16 {
		t.Fatalf("auto login capability parameters incomplete: %v", query)
	}
	if query.Get("organization_identity") != "required" {
		t.Fatal("auto login did not require organization identity")
	}

	tx := start.Result().Cookies()[0]
	callback := "/auth/callback?error=login_required&state=" + url.QueryEscape(query.Get("state"))
	response := callAuth(a, http.MethodGet, callback, "", tx, "")
	if response.Code != http.StatusFound {
		t.Fatalf("silent fallback HTTP %d %s", response.Code, response.Body.String())
	}
	if location := response.Header().Get("Location"); location != "http://localhost:5180/catalog?sso_auto=guest" {
		t.Fatalf("silent fallback location=%q", location)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == a.config.CookieName {
			t.Fatal("silent fallback published a session")
		}
	}

	replay := callAuth(a, http.MethodGet, callback, "", tx, "")
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("silent fallback replay HTTP %d", replay.Code)
	}
}

func TestSilentConsentRequiredStartsFreshNormalAuthorization(t *testing.T) {
	a, f := fixtureRuntime(t)
	start := callAuth(a, http.MethodGet, "/auth/auto-login?return_to="+url.QueryEscape("/credits?view=keys#section"), "", nil, "")
	if start.Code != http.StatusFound {
		t.Fatalf("auto login HTTP %d", start.Code)
	}
	silentTarget, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal("silent authorization URL invalid")
	}
	silentTX := loginTransactionCookie(t, a, start)
	silentCallback := "/auth/callback?error=consent_required&return_to=" + url.QueryEscape("/attacker") + "&state=" + url.QueryEscape(silentTarget.Query().Get("state"))
	continuation := callAuth(a, http.MethodGet, silentCallback, "", silentTX, "")
	if continuation.Code != http.StatusFound {
		t.Fatalf("consent continuation HTTP %d %s", continuation.Code, continuation.Body.String())
	}
	normalTarget, err := url.Parse(continuation.Header().Get("Location"))
	if err != nil {
		t.Fatal("normal authorization URL invalid")
	}
	normalQuery := normalTarget.Query()
	if normalQuery.Get("prompt") != "consent" {
		t.Fatalf("normal continuation prompt=%q", normalQuery.Get("prompt"))
	}
	for name, oldValue := range map[string]string{
		"state":          silentTarget.Query().Get("state"),
		"nonce":          silentTarget.Query().Get("nonce"),
		"code_challenge": silentTarget.Query().Get("code_challenge"),
	} {
		if newValue := normalQuery.Get(name); newValue == "" || newValue == oldValue {
			t.Fatalf("normal continuation %s was not fresh", name)
		}
	}
	if normalQuery.Get("code_challenge_method") != "S256" || normalQuery.Get("organization_identity") != "required" {
		t.Fatalf("normal continuation capabilities incomplete: %v", normalQuery)
	}
	normalTX := loginTransactionCookie(t, a, continuation)
	if normalTX.Value == silentTX.Value {
		t.Fatal("normal continuation reused silent transaction")
	}

	f.nonce = normalQuery.Get("nonce")
	normalCallback := "/auth/callback?code=fixture-code&state=" + url.QueryEscape(normalQuery.Get("state"))
	response := callAuth(a, http.MethodGet, normalCallback, "", normalTX, "")
	if response.Code != http.StatusFound {
		t.Fatalf("normal callback HTTP %d %s", response.Code, response.Body.String())
	}
	if location := response.Header().Get("Location"); location != "http://localhost:5180/credits?view=keys#section" {
		t.Fatalf("trusted return path=%q", location)
	}
	if sessionCookie(response, a) == nil {
		t.Fatal("normal callback did not publish a session")
	}
	replay := callAuth(a, http.MethodGet, silentCallback, "", silentTX, "")
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("silent callback replay HTTP %d", replay.Code)
	}
}

func TestSilentConsentContinuationIsOneShotAndKeepsExistingSession(t *testing.T) {
	a, f := fixtureRuntime(t)
	existing := loginFixture(t, a, f)
	start := callAuth(a, http.MethodGet, "/auth/auto-login?return_to=%2Fnext", "", nil, "")
	silentTarget, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal("silent authorization URL invalid")
	}
	silentTX := loginTransactionCookie(t, a, start)
	silentCallback := "/auth/callback?error=consent_required&state=" + url.QueryEscape(silentTarget.Query().Get("state"))
	continuation := callAuth(a, http.MethodGet, silentCallback, "", silentTX, "")
	if continuation.Code != http.StatusFound {
		t.Fatalf("consent continuation HTTP %d %s", continuation.Code, continuation.Body.String())
	}
	normalTarget, err := url.Parse(continuation.Header().Get("Location"))
	if err != nil {
		t.Fatal("normal authorization URL invalid")
	}
	normalTX := loginTransactionCookie(t, a, continuation)
	secondError := "/auth/callback?error=consent_required&state=" + url.QueryEscape(normalTarget.Query().Get("state"))
	response := callAuthWithCookies(a, http.MethodGet, secondError, existing, normalTX)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("second normal error HTTP %d %s", response.Code, response.Body.String())
	}
	if sessionCookie(response, a) != nil {
		t.Fatal("failed continuation replaced the existing session")
	}
	if callAuth(a, http.MethodGet, "/auth/session", "", existing, "").Code != http.StatusOK {
		t.Fatal("failed continuation cleared the existing session")
	}
	replay := callAuth(a, http.MethodGet, silentCallback, "", silentTX, "")
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("silent callback replay HTTP %d", replay.Code)
	}
}

func TestSilentConsentRequiredRejectsInvalidCallbacksWithoutContinuation(t *testing.T) {
	cases := []struct {
		name     string
		path     func(state string) string
		expire   bool
		wantCode int
	}{
		{name: "invalid-state", path: func(string) string { return "/auth/callback?error=consent_required&state=wrong" }, wantCode: http.StatusBadRequest},
		{name: "duplicate-state", path: func(state string) string {
			return "/auth/callback?error=consent_required&state=wrong&state=" + url.QueryEscape(state)
		}, wantCode: http.StatusBadRequest},
		{name: "unknown-error", path: func(state string) string { return "/auth/callback?error=invalid_scope&state=" + url.QueryEscape(state) }, wantCode: http.StatusBadRequest},
		{name: "error-with-code", path: func(state string) string {
			return "/auth/callback?error=consent_required&code=private&state=" + url.QueryEscape(state)
		}, wantCode: http.StatusBadRequest},
		{name: "duplicate-error", path: func(state string) string {
			return "/auth/callback?error=consent_required&error=login_required&state=" + url.QueryEscape(state)
		}, wantCode: http.StatusBadRequest},
		{name: "expired-transaction", path: func(state string) string {
			return "/auth/callback?error=consent_required&state=" + url.QueryEscape(state)
		}, expire: true, wantCode: http.StatusBadRequest},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			a, _ := fixtureRuntime(t)
			start := callAuth(a, http.MethodGet, "/auth/auto-login?return_to=%2Fnext", "", nil, "")
			target, err := url.Parse(start.Header().Get("Location"))
			if err != nil {
				t.Fatal("silent authorization URL invalid")
			}
			tx := loginTransactionCookie(t, a, start)
			if test.expire {
				if err := a.store.db.Del(context.Background(), a.store.prefix+"tx:"+tx.Value).Err(); err != nil {
					t.Fatal(err)
				}
			}
			response := callAuth(a, http.MethodGet, test.path(target.Query().Get("state")), "", tx, "")
			if response.Code != test.wantCode {
				t.Fatalf("HTTP %d, want %d: %s", response.Code, test.wantCode, response.Body.String())
			}
			if next := loginTransactionCookieOptional(a, response); next != nil {
				t.Fatal("invalid callback started a normal authorization")
			}
			if sessionCookie(response, a) != nil {
				t.Fatal("invalid callback published a session")
			}
		})
	}
}

func TestSilentConsentContinuationFailsClosedWhenDependenciesUnavailable(t *testing.T) {
	t.Run("provider", func(t *testing.T) {
		a, f := fixtureRuntime(t)
		start := callAuth(a, http.MethodGet, "/auth/auto-login?return_to=%2Fnext", "", nil, "")
		target, err := url.Parse(start.Header().Get("Location"))
		if err != nil {
			t.Fatal("silent authorization URL invalid")
		}
		tx := loginTransactionCookie(t, a, start)
		expireDiscoveryCache(t, a)
		f.unavailable = true
		callback := "/auth/callback?error=consent_required&state=" + url.QueryEscape(target.Query().Get("state"))
		response := callAuth(a, http.MethodGet, callback, "", tx, "")
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("provider unavailable HTTP %d %s", response.Code, response.Body.String())
		}
		if next := loginTransactionCookieOptional(a, response); next != nil || sessionCookie(response, a) != nil {
			t.Fatal("provider unavailable published continuation state or session")
		}
	})

	t.Run("redis", func(t *testing.T) {
		a, _ := fixtureRuntime(t)
		start := callAuth(a, http.MethodGet, "/auth/auto-login?return_to=%2Fnext", "", nil, "")
		target, err := url.Parse(start.Header().Get("Location"))
		if err != nil {
			t.Fatal("silent authorization URL invalid")
		}
		tx := loginTransactionCookie(t, a, start)
		original := a.store.db
		a.store.db = redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 20 * time.Millisecond, MaxRetries: -1})
		defer func() {
			_ = a.store.db.Close()
			a.store.db = original
		}()
		callback := "/auth/callback?error=consent_required&state=" + url.QueryEscape(target.Query().Get("state"))
		response := callAuth(a, http.MethodGet, callback, "", tx, "")
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("Redis unavailable HTTP %d %s", response.Code, response.Body.String())
		}
		if next := loginTransactionCookieOptional(a, response); next != nil || sessionCookie(response, a) != nil {
			t.Fatal("Redis unavailable published continuation state or session")
		}
	})
}

func TestSilentConsentContinuationWithCachedDiscoveryDoesNotPublishAuthority(t *testing.T) {
	a, f := fixtureRuntime(t)
	existing := loginFixture(t, a, f)
	start := callAuth(a, http.MethodGet, "/auth/auto-login?return_to=%2Fnext", "", nil, "")
	silentTarget, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal("silent authorization URL invalid")
	}
	silentTX := loginTransactionCookie(t, a, start)

	// Cached discovery can form navigation after the authority becomes unavailable,
	// but navigation alone must not mint or replace a session.
	f.unavailable = true
	silentCallback := "/auth/callback?error=consent_required&state=" + url.QueryEscape(silentTarget.Query().Get("state"))
	continuation := callAuth(a, http.MethodGet, silentCallback, "", silentTX, "")
	if continuation.Code != http.StatusFound {
		t.Fatalf("cached-discovery continuation HTTP %d %s", continuation.Code, continuation.Body.String())
	}
	normalTarget, err := url.Parse(continuation.Header().Get("Location"))
	if err != nil || normalTarget.Query().Get("prompt") != "consent" {
		t.Fatalf("cached-discovery normal authorization location=%q", continuation.Header().Get("Location"))
	}
	normalTX := loginTransactionCookie(t, a, continuation)
	if sessionCookie(continuation, a) != nil {
		t.Fatal("cached navigation published a session")
	}

	normalCallback := "/auth/callback?code=fixture-code&state=" + url.QueryEscape(normalTarget.Query().Get("state"))
	redemption := callAuthWithCookies(a, http.MethodGet, normalCallback, existing, normalTX)
	if redemption.Code != http.StatusUnauthorized {
		t.Fatalf("unavailable token redemption HTTP %d %s", redemption.Code, redemption.Body.String())
	}
	if sessionCookie(redemption, a) != nil {
		t.Fatal("failed redemption replaced the existing session")
	}
	f.unavailable = false
	if callAuth(a, http.MethodGet, "/auth/session", "", existing, "").Code != http.StatusOK {
		t.Fatal("failed redemption cleared the existing session")
	}
}

func TestAutoLoginRejectsSilentErrorBeforeStateValidation(t *testing.T) {
	a, _ := fixtureRuntime(t)
	start := callAuth(a, http.MethodGet, "/auth/auto-login?return_to=%2Fcatalog", "", nil, "")
	if start.Code != http.StatusFound {
		t.Fatalf("auto login HTTP %d", start.Code)
	}
	tx := start.Result().Cookies()[0]
	response := callAuth(a, http.MethodGet, "/auth/callback?error=login_required&state=wrong", "", tx, "")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unvalidated silent error HTTP %d %s", response.Code, response.Body.String())
	}
	if location := response.Header().Get("Location"); location != "" {
		t.Fatalf("unvalidated silent error redirected to %q", location)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == a.config.CookieName {
			t.Fatal("unvalidated silent error published a session")
		}
	}
}

func TestAutoLoginPreservesExistingReturnQueryWhenMarkingGuest(t *testing.T) {
	a, _ := fixtureRuntime(t)
	start := callAuth(a, http.MethodGet, "/auth/auto-login?return_to="+url.QueryEscape("/credits?view=keys#section"), "", nil, "")
	if start.Code != http.StatusFound {
		t.Fatalf("auto login HTTP %d", start.Code)
	}
	target, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal("auto login redirect invalid")
	}
	callback := "/auth/callback?error=interaction_required&state=" + url.QueryEscape(target.Query().Get("state"))
	response := callAuth(a, http.MethodGet, callback, "", start.Result().Cookies()[0], "")
	if response.Code != http.StatusFound {
		t.Fatalf("silent fallback HTTP %d %s", response.Code, response.Body.String())
	}
	if location := response.Header().Get("Location"); location != "http://localhost:5180/credits?sso_auto=guest&view=keys#section" {
		t.Fatalf("silent fallback location=%q", location)
	}
}

func TestSilentLoginErrorsAndGuestRedirectAreStrictlySeparated(t *testing.T) {
	for _, errorCode := range []string{"login_required", "interaction_required", "consent_required", "unmet_authentication_requirements", "access_denied", "server_error", "temporarily_unavailable"} {
		if !silentLoginUnavailable(url.Values{"error": {errorCode}}) {
			t.Fatalf("expected silent fallback for %q", errorCode)
		}
	}
	for name, query := range map[string]url.Values{
		"missing":           {},
		"duplicate":         {"error": {"login_required", "login_required"}},
		"with-code":         {"error": {"login_required"}, "code": {"authorization-code"}},
		"unexpected":        {"error": {"invalid_scope"}},
		"error-description": {"error_description": {"login_required"}},
	} {
		if silentLoginUnavailable(query) {
			t.Fatalf("accepted non-silent capability %s", name)
		}
	}

	const origin = "https://hub.example.com"
	if got, want := silentGuestRedirect(origin, "/"), origin+"/?sso_auto=guest"; got != want {
		t.Fatalf("root fallback=%q want=%q", got, want)
	}
	if got, want := silentGuestRedirect(origin, "/credits?view=keys&sso_auto=stale#section"), origin+"/credits?sso_auto=guest&view=keys#section"; got != want {
		t.Fatalf("query fallback=%q want=%q", got, want)
	}
}

func callAuthWithLogContext(a *Runtime, ctx context.Context, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "http://localhost:5180"+path, nil).WithContext(ctx)
	r.RequestURI = r.URL.RequestURI()
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}

func expireDiscoveryCache(t *testing.T, a *Runtime) {
	t.Helper()
	cache, ok := a.http.Transport.(*discoveryTransport)
	if !ok {
		t.Fatalf("unexpected HTTP transport %T", a.http.Transport)
	}
	cache.mu.Lock()
	cache.until = time.Now().Add(-time.Second)
	cache.mu.Unlock()
}

func callAuthWithCookies(a *Runtime, method, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://localhost:5180"+path, nil)
	r.RequestURI = r.URL.RequestURI()
	for _, cookie := range cookies {
		if cookie != nil {
			r.AddCookie(cookie)
		}
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}

func loginTransactionCookieOptional(a *Runtime, w *httptest.ResponseRecorder) *http.Cookie {
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == a.config.CookieName+"_login" && cookie.Value != "" && cookie.MaxAge > 0 {
			return cookie
		}
	}
	return nil
}

func loginTransactionCookie(t *testing.T, a *Runtime, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	cookie := loginTransactionCookieOptional(a, w)
	if cookie == nil {
		t.Fatal("login transaction cookie absent")
	}
	return cookie
}

func sessionCookie(w *httptest.ResponseRecorder, a *Runtime) *http.Cookie {
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == a.config.CookieName && cookie.Value != "" && cookie.MaxAge > 0 {
			return cookie
		}
	}
	return nil
}

func captureSilentLoginLogs(t *testing.T) func() []map[string]any {
	t.Helper()
	path := filepath.Join(t.TempDir(), "silent-login.log")
	config := logs.LogsConfig{"default": {{Writer: logs.WriterFile, Encoder: logs.EncoderStandard, Level: zapcore.InfoLevel, Logger: &lumberjack.Logger{Filename: path}}}}
	if err := logs.ReloadConfig("silent-login-test", config); err != nil {
		t.Fatal(err)
	}
	closed := false
	closeLogger := func() {
		if closed {
			return
		}
		closed = true
		if err := logs.ReloadConfig("-", nil); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(closeLogger)
	return func() []map[string]any {
		closeLogger()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(data)) == "" {
			return nil
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		entries := make([]map[string]any, 0, len(lines))
		for _, line := range lines {
			var entry map[string]any
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				t.Fatal(err)
			}
			entries = append(entries, entry)
		}
		return entries
	}
}

func TestSilentLoginUnavailableLogsOnlyAllowlistedReasons(t *testing.T) {
	readLogs := captureSilentLoginLogs(t)
	a, _ := fixtureRuntime(t)
	reasons := []string{"login_required", "interaction_required", "consent_required", "unmet_authentication_requirements", "access_denied", "server_error", "temporarily_unavailable"}
	seen := map[string]bool{}
	requestIDs := map[string]string{}
	for _, reason := range reasons {
		start := callAuth(a, http.MethodGet, "/auth/auto-login?return_to=%2Fcatalog", "", nil, "")
		if start.Code != http.StatusFound {
			t.Fatalf("auto login HTTP %d", start.Code)
		}
		target, err := url.Parse(start.Header().Get("Location"))
		if err != nil {
			t.Fatal("auto login redirect invalid")
		}
		state := target.Query().Get("state")
		nonce := target.Query().Get("nonce")
		requestID := "silent-request-" + reason
		ctx := requestid.WithContext(context.Background(), requestID)
		ctx = logs.WithContextFields(ctx,
			"authorization", "private-authorization",
			"cookie", "private-cookie",
			"access_token", "private-token",
			"state", state,
			"nonce", nonce,
			"code", "private-code",
			"user_id", "private-user",
			"organization_id", "private-organization",
			"url", "https://private.invalid/callback?secret=private-query",
		)
		callback := "/auth/callback?error=" + url.QueryEscape(reason) + "&state=" + url.QueryEscape(state)
		tx := start.Result().Cookies()[0]
		response := callAuthWithLogContext(a, ctx, callback, tx)
		if response.Code != http.StatusFound {
			t.Fatalf("%s fallback HTTP %d %s", reason, response.Code, response.Body.String())
		}
		location := response.Header().Get("Location")
		if reason == "consent_required" {
			target, err := url.Parse(location)
			if err != nil || target.Query().Get("prompt") != "consent" || target.Query().Get("state") == "" {
				t.Fatalf("%s normal continuation location=%q", reason, location)
			}
			if next := loginTransactionCookie(t, a, response); next.Value == tx.Value {
				t.Fatalf("%s reused silent transaction", reason)
			}
		} else if location != "http://localhost:5180/catalog?sso_auto=guest" {
			t.Fatalf("%s fallback location=%q", reason, location)
		}
		for _, cookie := range response.Result().Cookies() {
			if cookie.Name == a.config.CookieName {
				t.Fatalf("%s fallback published a session", reason)
			}
		}
		replay := callAuthWithLogContext(a, context.Background(), callback, tx)
		if replay.Code != http.StatusBadRequest {
			t.Fatalf("%s replay HTTP %d", reason, replay.Code)
		}
		seen[reason] = true
		requestIDs[reason] = requestID
	}
	entries := readLogs()
	diagnostics := make([]map[string]any, 0, len(reasons))
	for _, entry := range entries {
		if entry["msg"] == "logtobff.silent_login.unavailable" {
			diagnostics = append(diagnostics, entry)
		}
	}
	if len(diagnostics) != len(reasons) {
		t.Fatalf("silent diagnostic entries=%d, want %d", len(diagnostics), len(reasons))
	}
	for _, entry := range diagnostics {
		if entry["lvl"] != "INFO" {
			t.Fatalf("unexpected silent diagnostic entry: %v", entry)
		}
		reason, ok := entry["reason"].(string)
		if !ok || !seen[reason] {
			t.Fatalf("unexpected silent diagnostic reason: %v", entry["reason"])
		}
		if entry["request_id"] != requestIDs[reason] {
			t.Fatalf("silent diagnostic request identity mismatch: %v", entry)
		}
		delete(seen, reason)
		for _, field := range []string{"authorization", "cookie", "access_token", "state", "nonce", "code", "user_id", "organization_id", "url"} {
			if _, exists := entry[field]; exists {
				t.Fatalf("silent diagnostic retained forbidden field %q", field)
			}
		}
		encoded, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{"private-authorization", "private-cookie", "private-token", "private-code", "private-user", "private-organization", "private.invalid", "private-query"} {
			if strings.Contains(string(encoded), private) {
				t.Fatalf("silent diagnostic leaked %q", private)
			}
		}
	}
	if len(seen) != 0 {
		t.Fatalf("missing silent diagnostic reasons: %v", seen)
	}
}

func TestSilentLoginDiagnosticDoesNotLogSuccessfulAuthentication(t *testing.T) {
	readLogs := captureSilentLoginLogs(t)
	a, f := fixtureRuntime(t)
	if session := loginFixture(t, a, f); session == nil {
		t.Fatal("successful callback did not publish a session")
	}
	for _, entry := range readLogs() {
		if entry["msg"] == "logtobff.silent_login.unavailable" {
			t.Fatalf("successful authentication emitted silent fallback diagnostic: %v", entry)
		}
	}
}

func TestSilentLoginDiagnosticRejectsInvalidStateAndErrorInjection(t *testing.T) {
	readLogs := captureSilentLoginLogs(t)
	a, _ := fixtureRuntime(t)
	cases := []func(state string) string{
		func(string) string { return "/auth/callback?error=login_required&state=wrong" },
		func(state string) string {
			return "/auth/callback?error=" + url.QueryEscape("login_required\nforged") + "&state=" + url.QueryEscape(state)
		},
		func(state string) string {
			return "/auth/callback?error=login_required&code=private-code&state=" + url.QueryEscape(state)
		},
		func(state string) string {
			return "/auth/callback?error_description=login_required&state=" + url.QueryEscape(state)
		},
	}
	for index, callbackFor := range cases {
		start := callAuth(a, http.MethodGet, "/auth/auto-login?return_to=%2F", "", nil, "")
		if start.Code != http.StatusFound {
			t.Fatalf("case %d auto login HTTP %d", index, start.Code)
		}
		target, err := url.Parse(start.Header().Get("Location"))
		if err != nil {
			t.Fatal("auto login redirect invalid")
		}
		response := callAuthWithLogContext(a, context.Background(), callbackFor(target.Query().Get("state")), start.Result().Cookies()[0])
		if response.Code != http.StatusBadRequest {
			t.Fatalf("case %d invalid callback HTTP %d %s", index, response.Code, response.Body.String())
		}
		for _, cookie := range response.Result().Cookies() {
			if cookie.Name == a.config.CookieName {
				t.Fatalf("case %d published a session", index)
			}
		}
	}
	for _, entry := range readLogs() {
		if entry["msg"] == "logtobff.silent_login.unavailable" {
			t.Fatalf("invalid callback emitted silent fallback diagnostic: %v", entry)
		}
	}
}
