package logtobff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
	"unicode/utf8"

	"github.com/JUXON-AI/jxpkg/logs"
)

const (
	_resourceGrantRevokePath = "/api/my-account/resource-grants/revoke"
	_maxGrantIDBytes         = 128
	_maxGrantResourceBytes   = 512
	_maxRevokeBodyBytes      = 4 << 10
)

type resourceGrantRevokeRequest struct {
	Resource         string `json:"resource"`
	GrantID          string `json:"grant_id"`
	OrganizationID   string `json:"organization_id"`
	ExpectedRevision string `json:"expected_revision"`
}

// revokeResourceGrant re-reads the same browser session immediately before the
// native mutation. The remote endpoint receives only startup-bounded resource
// and grant fields plus the selected organization/revision from that session.
// jxlog:business
func (a *Runtime) revokeResourceGrant(ctx context.Context, id string, expected Principal, resource, grantID string) (resultErr error) {
	logs.InfoContextw(ctx, "logtobff.Runtime.revokeResourceGrant 进入")
	defer func() {
		logs.InfoContextw(ctx, "logtobff.Runtime.revokeResourceGrant 退出", "failed", resultErr != nil)
	}()
	if !validGrantResource(resource) || !validGrantID(grantID) || expected.UserID == "" || expected.OrganizationID == "" || expected.OrganizationRevision == "" {
		return ErrAuthorizationChanged
	}
	ctx, cancel := context.WithTimeout(ctx, _authenticationTimeout)
	defer cancel()
	value, err := a.beginIdentity(ctx, id)
	if err != nil {
		return authorizationError(err)
	}
	before := *value
	if value.Subject != expected.UserID || value.Organization != expected.OrganizationID || value.Revision != expected.OrganizationRevision {
		return ErrAuthorizationChanged
	}
	logs.DebugContext(ctx, "logtobff.Runtime.revokeResourceGrant session_revalidated")
	_, _, currentErr := a.currentRequest(ctx, value)
	valid := currentErr == nil && value.Subject == expected.UserID && value.Organization == expected.OrganizationID && value.Revision == expected.OrganizationRevision
	if currentErr == nil {
		// This route cannot send a replacement browser Cookie. The next session
		// request adopts any central identity revision after this mutation.
		value.Organization, value.Revision = before.Organization, before.Revision
	} else if authorizationError(currentErr) == ErrUnavailable {
		value.Organization = ""
	}

	var remoteErr error
	if valid {
		token, tokenErr := a.sdk(ctx, value.SDK).GetAccessToken("")
		if tokenErr != nil || token.Token == "" || token.ExpiresAt <= time.Now().Add(_authenticationTimeout).Unix() {
			remoteErr = ErrUnavailable
		} else {
			logs.DebugContext(ctx, "logtobff.Runtime.revokeResourceGrant remote_start")
			remoteErr = a.revokeAtAccount(ctx, token.Token, resourceGrantRevokeRequest{
				Resource: resource, GrantID: grantID,
				OrganizationID: expected.OrganizationID, ExpectedRevision: expected.OrganizationRevision,
			})
		}
	}
	// Commit only SDK rotation under the original identity. A changed central
	// organization remains for the next Cookie-rotating session request.
	commitCtx, commitCancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer commitCancel()
	if err := a.finishIdentity(commitCtx, id, id, &before, value, currentErr != nil && authorizationError(currentErr) == ErrAuthorizationChanged); err != nil {
		return ErrUnavailable
	}
	logs.DebugContext(ctx, "logtobff.Runtime.revokeResourceGrant sdk_state_committed")
	if currentErr != nil {
		return authorizationError(currentErr)
	}
	if !valid || remoteErr != nil {
		if !valid {
			return ErrAuthorizationChanged
		}
		return remoteErr
	}
	return nil
}

// jxlog:business
func (a *Runtime) revokeAtAccount(ctx context.Context, accessToken string, input resourceGrantRevokeRequest) (resultErr error) {
	logs.InfoContextw(ctx, "logtobff.Runtime.revokeAtAccount 进入")
	defer func() {
		logs.InfoContextw(ctx, "logtobff.Runtime.revokeAtAccount 退出", "failed", resultErr != nil)
	}()
	body, err := json.Marshal(input)
	if err != nil || len(body) > _maxRevokeBodyBytes {
		return ErrUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.config.Endpoint+_resourceGrantRevokePath, bytes.NewReader(body))
	if err != nil {
		return ErrUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	response, err := a.http.Do(request)
	if err != nil {
		return ErrUnavailable
	}
	logs.DebugContextw(ctx, "logtobff.Runtime.revokeAtAccount response_received", "upstream_status", response.StatusCode)
	var (
		read              int64
		readErr, closeErr error
	)
	read, readErr = io.Copy(io.Discard, io.LimitReader(response.Body, 1))
	closeErr = response.Body.Close()
	if closeErr != nil {
		// Close releases local response resources after the fixed endpoint's
		// status is known; it is observed here but is not a remote commit signal.
		logs.WarnContextw(ctx, "logtobff.Runtime.revokeAtAccount response_close_failed", "upstream_status", response.StatusCode)
	}
	if readErr != nil || response.StatusCode == http.StatusNoContent && (read != 0 || response.ContentLength > 0) {
		return ErrUnavailable
	}
	switch response.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict:
		return ErrAuthorizationChanged
	default:
		return ErrUnavailable
	}
}

// jxlog:nonbusiness 纯字节边界校验，无 I/O、日志上下文或状态迁移。
func validGrantID(value string) bool {
	if value == "" || len(value) > _maxGrantIDBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

// jxlog:nonbusiness 纯资源 URI 校验，无 I/O、日志上下文或状态迁移。
func validGrantResource(value string) bool {
	if value == "" || len(value) > _maxGrantResourceBytes || !utf8.ValidString(value) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	var (
		host  = parsed.Hostname()
		local = host == "localhost" || host == "127.0.0.1" || host == "::1"
	)
	return parsed.String() == value && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.RawPath == "" && parsed.Opaque == "" && (parsed.Scheme == "https" || parsed.Scheme == "http" && local)
}

// jxlog:nonbusiness 固定错误分类，不处理或记录原始错误。
func authorizationError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, _errMissing) || errors.Is(err, _errBusy) || errors.Is(err, _errInvalid) {
		return ErrAuthorizationChanged
	}
	var denied *accessError
	if errors.As(err, &denied) && denied.status >= 400 && denied.status < 500 {
		return ErrAuthorizationChanged
	}
	return ErrUnavailable
}
