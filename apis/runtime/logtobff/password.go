package logtobff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/JUXON-AI/jxpkg/logs"
)

type passwordVerifierKey struct{}

const accountPasswordVerificationPath = "/api/verifications/password"

// ErrPasswordRejected means the identity provider did not verify the supplied password.
var ErrPasswordRejected = errors.New("current password rejected")

// VerifyCurrentPassword checks the password of the request's authorized browser
// subject. It returns only the outcome, discarding the provider's verification
// record. A protected handler should use success only in the same request.
// jxlog:nonbusiness delegates to the request-scoped verified session capability.
func VerifyCurrentPassword(ctx context.Context, password string) error {
	verify, ok := ctx.Value(passwordVerifierKey{}).(func(context.Context, string) error)
	if !ok {
		return ErrAuthorizationChanged
	}
	if password == "" || len(password) > 1024 || !utf8.ValidString(password) {
		return ErrPasswordRejected
	}
	return verify(ctx, password)
}

// jxlog:business
func (a *Runtime) verifyCurrentPassword(ctx context.Context, sessionID string, expected Principal, password string) (err error) {
	logs.InfoContextw(ctx, "logtobff.verify_current_password.enter")
	defer func() { logs.InfoContextw(ctx, "logtobff.verify_current_password.exit", "failed", err != nil) }()
	ctx, cancel := context.WithTimeout(ctx, _authenticationTimeout)
	defer cancel()
	value, err := a.beginIdentity(ctx, sessionID)
	if err != nil {
		return authorizationError(err)
	}
	if value.Subject != expected.UserID || value.Organization != expected.OrganizationID || value.Revision != expected.OrganizationRevision || expected.ExpiresAt <= time.Now().Unix() {
		return ErrAuthorizationChanged
	}
	token, err := a.sdk(ctx, value.SDK).GetAccessToken("")
	if err != nil || token.Token == "" {
		return ErrUnavailable
	}
	if err := a.verifyPasswordAtAccount(ctx, token.Token, password); err != nil {
		return err
	}
	return a.revalidate(ctx, sessionID, expected, expected.Permissions)
}

// jxlog:nonbusiness calls only the configured provider and returns fixed errors to its owner.
func (a *Runtime) verifyPasswordAtAccount(ctx context.Context, token, password string) error {
	body, err := json.Marshal(struct {
		Password string `json:"password"`
	}{password})
	if err != nil {
		return ErrUnavailable
	}
	defer clear(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.config.Endpoint+accountPasswordVerificationPath, bytes.NewReader(body))
	if err != nil {
		return ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := a.http.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusCreated:
		var receipt struct {
			ID        string    `json:"verificationRecordId"`
			ExpiresAt time.Time `json:"expiresAt"`
		}
		decoder := json.NewDecoder(io.LimitReader(response.Body, 4096))
		if err := decoder.Decode(&receipt); err != nil || receipt.ID == "" || !receipt.ExpiresAt.After(time.Now()) {
			return ErrUnavailable
		}
		return nil
	case http.StatusUnprocessableEntity:
		return ErrPasswordRejected
	default:
		return ErrUnavailable
	}
}

// jxlog:nonbusiness builds a redirect to the configured provider for the current session.
func (a *Runtime) changePassword(r *http.Request, value *session) result {
	redirects := r.URL.Query()["return_to"]
	if len(redirects) > 1 {
		return problem(http.StatusBadRequest, "return_to_invalid")
	}
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}
	parsed, err := url.Parse(returnTo)
	if err != nil || len(returnTo) > 512 || !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") ||
		strings.ContainsAny(returnTo, "\\\r\n") || parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" || parsed.ForceQuery || strings.ContainsAny(parsed.Fragment, "?&") {
		return problem(http.StatusBadRequest, "return_to_invalid")
	}
	if _, _, err := a.currentRequest(r.Context(), value); err != nil {
		return classify(err)
	}
	query := url.Values{
		"redirect":     {a.config.Origin + returnTo},
		"show_success": {"true"},
	}
	return result{status: http.StatusFound, redirect: a.config.Endpoint + "/account/password?" + query.Encode()}
}
