package logtobff

import (
	"net/http"
	"net/url"
	"testing"
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
