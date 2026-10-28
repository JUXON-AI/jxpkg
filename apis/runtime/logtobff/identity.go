package logtobff

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/logto-io/go/v2/client"
	"github.com/logto-io/go/v2/core"
)

type organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type profile struct {
	Subject       string   `json:"sub"`
	Username      string   `json:"username"`
	Name          string   `json:"name"`
	Avatar        string   `json:"picture"`
	Email         string   `json:"email"`
	Organizations []string `json:"organizations"`
	Roles         []string `json:"organization_roles"`
}
type signedClaims struct {
	jwt.RegisteredClaims

	ClientID            string   `json:"client_id"`
	OrganizationID      string   `json:"organization_id"`
	Scope               string   `json:"scope"`
	DepartmentIDs       []string `json:"department_ids"`
	PrimaryDepartmentID *string  `json:"primary_department_id"`
}
type accessError struct {
	status int
	code   string
}

func (e *accessError) Error() string { return e.code }
func providerFailure(response *http.Response, account bool) error {
	var body struct {
		Error string `json:"error"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&body) != nil {
		return errors.New("invalid provider response")
	}
	if (account && response.StatusCode == 401) || (!account && response.StatusCode == 400 && body.Error == "invalid_grant") {
		return &accessError{status: 401, code: "session_invalid"}
	}
	if response.StatusCode == 403 || (response.StatusCode == 400 && body.Error == "access_denied") {
		return &accessError{status: 403, code: "organization_access_denied"}
	}
	return errors.New("provider unavailable")
}
func (a *Runtime) sdk(ctx context.Context, values map[string]string) *client.LogtoClient {
	var resources []string
	if a.config.APIResource != "" {
		resources = []string{a.config.APIResource}
	}
	return client.NewLogtoClient(&client.LogtoConfig{Endpoint: a.config.Endpoint, AppId: a.config.ClientID, AppSecret: a.config.ClientSecret, BaseUrl: a.config.Origin, Resources: resources, Scopes: append([]string{core.UserScopeOrganizations}, a.config.Scopes...)}, sdkStorage(values), client.WithHttpClient(a.http), client.WithContext(ctx))
}

type sdkStorage map[string]string

func (s sdkStorage) GetItem(key string) string { return s[key] }
func (s sdkStorage) SetItem(key, value string) { s[key] = value }
func (a *Runtime) login(w http.ResponseWriter, r *http.Request) {
	a.startLogin(w, r, "")
}

// autoLogin performs one silent authorization attempt. The frontend uses this
// fixed route only when the product has no browser session; prompt=none keeps
// the public page usable when the central browser has no reusable authority.
func (a *Runtime) autoLogin(w http.ResponseWriter, r *http.Request) {
	a.startLogin(w, r, "none")
}

func (a *Runtime) startLogin(w http.ResponseWriter, r *http.Request, prompt string) {
	ctx, cancel := context.WithTimeout(r.Context(), _authenticationTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	if len(r.Header.Values("Authorization")) != 0 || len(r.URL.Query()["return_to"]) > 1 {
		fail(w, r, 400, "login_request_invalid")
		return
	}
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}
	parsedReturn, parseErr := url.Parse(returnTo)
	if parseErr != nil || len(returnTo) > 2048 || !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") || strings.ContainsAny(returnTo, "\\\r\n") || parsedReturn.IsAbs() || parsedReturn.Host != "" {
		fail(w, r, 400, "return_to_invalid")
		return
	}
	values := map[string]string{}
	nonce, err := a.store.opaque()
	if err != nil {
		fail(w, r, 503, "login_entropy_unavailable")
		return
	}
	target, err := a.sdk(r.Context(), values).SignIn(&client.SignInOptions{
		RedirectUri: a.config.Origin + "/auth/callback",
		Prompt:      prompt,
		ExtraParams: map[string]string{"nonce": nonce, "organization_identity": "required"},
	})
	if err != nil {
		fail(w, r, 503, "login_provider_unavailable")
		return
	}
	authorizationURL, err := url.Parse(target)
	if err != nil || authorizationURL.Query().Get("state") == "" {
		fail(w, r, 503, "login_state_unavailable")
		return
	}
	id, _, err := a.store.start(r.Context(), transaction{
		SDK:      values,
		Nonce:    nonce,
		State:    authorizationURL.Query().Get("state"),
		ReturnTo: returnTo,
		Silent:   prompt == "none",
	})
	if err != nil {
		fail(w, r, 503, "login_store_unavailable")
		return
	}
	a.setCookie(w, a.config.CookieName+"_login", id, 300)
	http.Redirect(w, r, target, 302)
}

// silentLoginUnavailable accepts only an OAuth error after the one-time
// transaction and state checks have succeeded. It never turns guest navigation
// into an authentication decision.
func silentLoginUnavailable(query url.Values) bool {
	if len(query["error"]) != 1 || len(query["code"]) != 0 {
		return false
	}
	switch query.Get("error") {
	case "login_required", "interaction_required", "consent_required", "unmet_authentication_requirements", "access_denied", "server_error", "temporarily_unavailable":
		return true
	default:
		return false
	}
}

func silentGuestRedirect(origin, returnTo string) string {
	target, err := url.Parse(returnTo)
	if err != nil {
		return origin + "/?sso_auto=guest"
	}
	query := target.Query()
	query.Set("sso_auto", "guest")
	target.RawQuery = query.Encode()
	return origin + target.String()
}

func (a *Runtime) callback(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), _authenticationTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	if len(r.CookiesNamed(a.config.CookieName+"_login")) != 1 {
		fail(w, r, 400, "transaction_missing_or_ambiguous")
		return
	}
	cookie, _ := r.Cookie(a.config.CookieName + "_login")
	a.setCookie(w, a.config.CookieName+"_login", "", -1)
	tx, err := a.store.consume(r.Context(), cookie.Value)
	if err != nil {
		status := 503
		if errors.Is(err, _errMissing) {
			status = 400
		}
		fail(w, r, status, "transaction_consumed_expired_or_unavailable")
		return
	}
	q := r.URL.Query()
	if len(q["state"]) != 1 || !equalCSRF(q.Get("state"), tx.State) {
		fail(w, r, 400, "callback_state_invalid")
		return
	}
	if tx.Silent && silentLoginUnavailable(q) {
		// Consuming the transaction and validating state happen before this branch.
		// The guest marker is navigation state only; no authority is published.
		http.Redirect(w, r, silentGuestRedirect(a.config.Origin, tx.ReturnTo), http.StatusFound)
		return
	}
	if len(q["error"]) == 1 && q.Get("error") == "access_denied" && len(q["code"]) == 0 {
		http.Redirect(w, r, a.config.Origin+"/login-cancelled", 302)
		return
	}
	if len(q["state"]) != 1 || len(q["code"]) != 1 || q.Get("code") == "" || len(q["error"]) != 0 {
		fail(w, r, 400, "callback_invalid")
		return
	}
	sdk := a.sdk(r.Context(), tx.SDK)
	// 共享访问日志把 RequestURI 脱敏为 path；SDK 以固定 Origin 和 RequestURI 重组 callback，
	// 因此只给 SDK 一份恢复 query 的请求副本，原始请求继续保持脱敏状态。
	sdkRequest := r.Clone(r.Context())
	sdkRequest.RequestURI = sdkRequest.URL.RequestURI()
	if sdk.HandleSignInCallback(sdkRequest) != nil {
		fail(w, r, 401, "callback_rejected")
		return
	}
	verified, err := a.verifier.Verify(oidc.ClientContext(r.Context(), a.http), sdk.GetIdToken())
	if err != nil || !equalCSRF(verified.Nonce, tx.Nonce) || verified.Subject == "" || sdk.GetRefreshToken() == "" {
		fail(w, r, 401, "identity_invalid")
		return
	}
	var identity struct {
		OrganizationID string `json:"organization_id"`
		Revision       string `json:"organization_identity_revision"`
	}
	if verified.Claims(&identity) != nil || !_orgPattern.MatchString(identity.OrganizationID) || !validRevision(identity.Revision) {
		fail(w, r, 401, "organization_identity_missing")
		return
	}
	csrf, err := a.store.opaque()
	if err != nil {
		fail(w, r, 503, "session_entropy_unavailable")
		return
	}
	now := a.store.nowTime()
	value := &session{
		SDK:             tx.SDK,
		Subject:         verified.Subject,
		Organization:    identity.OrganizationID,
		Revision:        identity.Revision,
		CSRF:            csrf,
		Until:           now.Add(sessionIdleLifetime),
		PolicyVersion:   sessionPolicyVersion,
		AuthenticatedAt: now,
		IdleUntil:       now.Add(sessionIdleLifetime),
		AbsoluteUntil:   now.Add(sessionAbsoluteLifetime),
	}
	if a.config.APIResource == "" {
		if err := a.prepareIdentity(r.Context(), value); err != nil {
			outcome := classify(err)
			fail(w, r, outcome.status, "identity_unavailable")
			return
		}
	}
	if _, _, err := a.currentRequest(r.Context(), value); err != nil {
		outcome := classify(err)
		fail(w, r, outcome.status, "organization_identity_unavailable")
		return
	}
	if value.Organization != identity.OrganizationID || value.Revision != identity.Revision {
		fail(w, r, 409, "organization_identity_changed")
		return
	}
	if a.config.APIResource != "" {
		if _, err := a.organizationClaims(r.Context(), value, value.Organization); err != nil {
			outcome := classify(err)
			fail(w, r, outcome.status, "organization_token_unavailable")
			return
		}
	}
	previous := ""
	if old, e := r.Cookie(a.config.CookieName); e == nil {
		previous = old.Value
	}
	next, err := a.store.create(r.Context(), value, previous)
	if err != nil {
		fail(w, r, 503, "session_store_unavailable")
		return
	}
	a.setCookie(w, a.config.CookieName, next, sessionCookieMaxAge(value, a.store.nowTime()))
	http.Redirect(w, r, a.config.Origin+tx.ReturnTo, 302)
}

func validRevision(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 53)
	return err == nil && parsed > 0 && strconv.FormatUint(parsed, 10) == value
}
func sdkFailure(err error) error {
	if errors.Is(err, client.ErrNotAuthenticated) {
		return &accessError{status: 401, code: "session_invalid"}
	}
	var response *core.ResponseError
	if errors.As(err, &response) && (response.StatusCode == 403 || response.ErrorCode == "access_denied") {
		return &accessError{status: 403, code: "organization_access_denied"}
	}
	return errors.New("identity provider unavailable")
}

// 用户 Token 按 SDK 有效期复用；资源模式仍实时签发组织 Token，保持部门/角色撤销语义。
// 固定 SDK v2 的用户缓存键为 @，保留它以免组织刷新连带触发用户刷新。
func (a *Runtime) token(ctx context.Context, value *session, org string) (string, error) {
	if value.SDK == nil {
		return "", &accessError{status: 401, code: "session_invalid"}
	}
	resource := ""
	if org != "" {
		resource = a.config.APIResource
		cache := map[string]client.AccessToken{}
		if data := value.SDK[client.StorageKeyAccessTokenMap]; data != "" {
			if json.Unmarshal([]byte(data), &cache) != nil {
				return "", errors.New("invalid stored token cache")
			}
		}
		for key := range cache {
			if key != "@" {
				delete(cache, key)
			}
		}
		data, err := json.Marshal(cache)
		if err != nil {
			return "", err
		}
		value.SDK[client.StorageKeyAccessTokenMap] = string(data)
	}
	token, err := a.sdk(ctx, value.SDK).GetAccessTokenWithOptions(client.GetAccessTokenOptions{Resource: resource, OrganizationId: org})
	if err != nil {
		return "", sdkFailure(err)
	}
	return token.Token, nil
}
func (a *Runtime) refresh(ctx context.Context, value *session) (profile, error) {
	if _, err := a.token(ctx, value, ""); err != nil {
		return profile{}, err
	}
	raw, err := a.sdk(ctx, value.SDK).FetchUserInfo()
	if err != nil {
		var response *core.ResponseError
		if errors.As(err, &response) && response.StatusCode == http.StatusUnauthorized {
			return profile{}, &accessError{status: 401, code: "session_invalid"}
		}
		return profile{}, sdkFailure(err)
	}
	data, err := json.Marshal(raw)
	var user profile
	if err != nil || json.Unmarshal(data, &user) != nil || user.Subject != value.Subject {
		return profile{}, &accessError{status: 401, code: "subject_mismatch"}
	}
	return user, nil
}
func (a *Runtime) organizations(ctx context.Context, value *session) ([]organization, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", a.config.Endpoint+"/api/my-account/organization-identity", nil)
	if err != nil {
		return nil, err
	}
	token, tokenErr := a.sdk(ctx, value.SDK).GetAccessToken("")
	if tokenErr != nil {
		return nil, sdkFailure(tokenErr)
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	response, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, providerFailure(response, true /* account */)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("invalid directory response")
	}
	var identity struct {
		Organizations  []organization `json:"organizations"`
		OrganizationID string         `json:"organization_id"`
		Revision       string         `json:"revision"`
	}
	if json.Unmarshal(data, &identity) != nil || identity.Organizations == nil || len(identity.Organizations) > 1000 || !validRevision(identity.Revision) || !_orgPattern.MatchString(identity.OrganizationID) {
		return nil, errors.New("invalid directory")
	}
	rows := identity.Organizations
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		if !_orgPattern.MatchString(row.ID) || len(row.Name) > 512 || seen[row.ID] {
			return nil, errors.New("invalid directory entry")
		}
		seen[row.ID] = true
	}
	if !contains(rows, identity.OrganizationID) {
		return nil, &accessError{status: 403, code: "organization_not_enabled_for_app"}
	}
	value.Organization, value.Revision = identity.OrganizationID, identity.Revision
	return rows, nil
}
func contains(rows []organization, id string) bool {
	for _, row := range rows {
		if row.ID == id {
			return true
		}
	}
	return false
}
func (a *Runtime) currentRequest(ctx context.Context, value *session) (profile, []organization, error) {
	var user profile
	if a.config.APIResource == "" {
		if value.Profile == nil {
			return user, nil, errors.New("session profile unavailable")
		}
		user = *value.Profile
	} else {
		var err error
		user, err = a.refresh(ctx, value)
		if err != nil {
			value.Organization = ""
			return user, nil, err
		}
	}
	rows, err := a.organizations(ctx, value)
	if err != nil {
		value.Organization = ""
		return user, nil, err
	}
	if value.Organization != "" && !contains(rows, value.Organization) {
		value.Organization = ""
		return user, rows, &accessError{status: 403, code: "organization_access_revoked"}
	}
	return user, rows, nil
}
func view(value *session, user profile, rows []organization, deadline time.Time) map[string]any {
	result := map[string]any{"authenticated": true, "organizations": rows, "organization_id": value.Organization, "organization_revision": value.Revision, "expires_at": deadline.Unix(), "csrf_token": value.CSRF}
	if value.Organization != "" {
		result["user"] = user
		roles := []string{}
		for _, role := range user.Roles {
			if strings.HasPrefix(role, value.Organization+":") {
				roles = append(roles, strings.TrimPrefix(role, value.Organization+":"))
			}
		}
		result["roles"] = roles
	}
	return result
}
func (a *Runtime) sessionView(r *http.Request, value *session) result {
	user, rows, err := a.currentRequest(r.Context(), value)
	if err != nil {
		return classify(err)
	}
	data, err := a.sessionViewData(r.Context(), value, user, rows)
	if err != nil {
		return classify(err)
	}
	return result{status: 200, data: data}
}

func (a *Runtime) sessionViewData(ctx context.Context, value *session, user profile, rows []organization) (map[string]any, error) {
	deadline, err := sessionDeadline(value, a.store.nowTime())
	if err != nil {
		return nil, err
	}
	data := view(value, user, rows, deadline)
	data["permissions"] = []string{}
	if value.Organization != "" && a.config.APIResource != "" {
		claims, err := a.organizationClaims(ctx, value, value.Organization)
		if err != nil {
			return nil, err
		}
		data["permissions"] = strings.Fields(claims.Scope)
	}
	return data, nil
}
func (a *Runtime) csrfValid(r *http.Request, value *session) bool {
	return len(r.Header.Values("Origin")) == 1 && len(r.Header.Values("X-CSRF-Token")) == 1 && r.Header.Get("Origin") == a.config.Origin && value.CSRF != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(value.CSRF)) == 1
}
func (a *Runtime) verify(ctx context.Context, raw, org, clientID string) (*signedClaims, error) {
	if !_orgPattern.MatchString(org) || len(raw) > 32768 {
		return nil, errors.New("invalid credential")
	}
	var claims signedClaims
	parsed, _, err := jwt.NewParser().ParseUnverified(raw, &claims)
	if err != nil || (parsed.Method.Alg() != "ES384" && parsed.Method.Alg() != "RS256") {
		return nil, errors.New("unsupported credential")
	}
	payload, err := a.keys.VerifySignature(ctx, raw)
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(payload, &claims) != nil {
		return nil, errors.New("invalid claims")
	}
	validator := jwt.NewValidator(jwt.WithIssuer(a.config.Endpoint+"/oidc"), jwt.WithAudience(a.config.APIResource), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if validator.Validate(&claims) != nil || claims.Subject == "" || claims.ClientID != clientID || claims.OrganizationID != org {
		return nil, errors.New("invalid API claims")
	}
	return &claims, nil
}
func (a *Runtime) organizationClaims(ctx context.Context, value *session, org string) (*signedClaims, error) {
	raw, err := a.token(ctx, value, org)
	if err != nil {
		return nil, err
	}
	claims, err := a.verify(ctx, raw, org, a.config.ClientID)
	if err != nil || claims.Subject != value.Subject {
		return nil, &accessError{status: 401, code: "api_credential_invalid"}
	}
	return claims, nil
}
func hasScope(claims *signedClaims, scope string) bool {
	for _, item := range strings.Fields(claims.Scope) {
		if item == scope {
			return true
		}
	}
	return false
}

// jxlog:business
func (a *Runtime) logout(r *http.Request, value *session) (outcome result) {
	logs.InfoContextw(r.Context(), "logtobff.Runtime.logout 进入")
	defer func() {
		logs.InfoContextw(r.Context(), "logtobff.Runtime.logout 退出", "status", outcome.status)
	}()
	if !a.csrfValid(r, value) {
		logs.WarnContextw(r.Context(), "logtobff.Runtime.logout 失败", "reason", "csrf_rejected")
		outcome = problem(403, "csrf_rejected")
		outcome.failureHandled = true
		return outcome
	}
	var (
		failure    = problem(503, "browser_logout_unavailable")
		token, err = a.sdk(r.Context(), value.SDK).GetAccessToken("")
	)
	failure.failureHandled = true
	if err != nil || token.Token == "" {
		logs.WarnContextw(r.Context(), "logtobff.Runtime.logout 失败", "reason", "access_token_unavailable")
		return failure
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, a.config.Endpoint+"/api/my-account/browser-session/logout", nil)
	if err != nil {
		logs.WarnContextw(r.Context(), "logtobff.Runtime.logout 失败", "reason", "request_unavailable")
		return failure
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	response, err := a.http.Do(req)
	if err != nil {
		logs.WarnContextw(r.Context(), "logtobff.Runtime.logout 失败", "reason", "center_unavailable")
		return failure
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			logs.WarnContextw(r.Context(), "logtobff.Runtime.logout 失败", "reason", "response_close_failed")
			outcome = failure
		}
	}()
	// A rejected bearer no longer authorizes this local session. Expire only
	// that capability; never retry the mutation against a newer SSO session.
	if response.StatusCode == http.StatusUnauthorized {
		logs.WarnContextw(r.Context(), "logtobff.Runtime.logout 失败", "reason", "center_session_rejected", "upstream_status", response.StatusCode)
		outcome = problem(http.StatusUnauthorized, "session_invalid")
		outcome.failureHandled = true
		return outcome
	}
	if response.StatusCode != http.StatusNoContent {
		logs.WarnContextw(r.Context(), "logtobff.Runtime.logout 失败", "reason", "center_status_rejected", "upstream_status", response.StatusCode)
		return failure
	}
	return result{status: 200, remove: true, data: map[string]string{"redirect_uri": a.config.Origin + "/"}}
}
func equalCSRF(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
