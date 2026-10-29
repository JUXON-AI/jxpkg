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

	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/JUXON-AI/jxpkg/requestid"
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
		if location := response.Header().Get("Location"); location != "http://localhost:5180/catalog?sso_auto=guest" {
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
