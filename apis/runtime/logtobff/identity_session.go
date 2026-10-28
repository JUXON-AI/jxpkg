package logtobff

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/logto-io/go/v2/client"
)

// prepareIdentity 按分钟更新展示资料，刷新时同步更新；授权状态由在线 identity 接口确认。
// Token 至少覆盖整个认证预算，解锁后的 SDK 读取不得自行轮换 refresh token。
func (a *Runtime) prepareIdentity(ctx context.Context, value *session) error {
	if value.SDK == nil {
		return &accessError{status: 401, code: "session_invalid"}
	}
	previous := value.SDK[client.StorageKeyAccessTokenMap]
	token, err := a.sdk(ctx, value.SDK).GetAccessToken("")
	if err != nil {
		return sdkFailure(err)
	}
	if token.ExpiresAt <= time.Now().Add(_authenticationTimeout).Unix() {
		delete(value.SDK, client.StorageKeyAccessTokenMap)
		token, err = a.sdk(ctx, value.SDK).GetAccessToken("")
		if err != nil {
			return sdkFailure(err)
		}
	}
	if token.ExpiresAt <= time.Now().Add(_authenticationTimeout).Unix() {
		return errors.New("identity token lifetime insufficient")
	}
	claims, err := a.sdk(ctx, value.SDK).GetIdTokenClaims()
	if err != nil || claims.Sub != value.Subject {
		return &accessError{status: 401, code: "subject_mismatch"}
	}
	if value.Profile == nil || !time.Now().Before(value.ProfileUntil) || previous != value.SDK[client.StorageKeyAccessTokenMap] {
		user, err := a.refresh(ctx, value)
		if err != nil {
			return err
		}
		if len(user.Username) > 512 || len(user.Name) > 512 || len(user.Avatar) > 4096 || len(user.Email) > 320 {
			return errors.New("identity profile too large")
		}
		// 部门、角色不由展示缓存发布，纯会话调用方不能把它当授权依据。
		user.Organizations, user.Roles = nil, nil
		value.Profile = &user
		value.ProfileUntil = time.Now().Add(time.Minute)
	}
	return nil
}

// beginIdentity 在短租约内持久化凭据轮换，随后释放租约供普通请求并行在线复核。
func (a *Runtime) beginIdentity(ctx context.Context, id string) (*session, error) {
	started := time.Now()
	value, owner, err := a.store.acquire(ctx, id)
	recordIdentityPhase(ctx, "bff.begin.acquire", started)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			a.store.release(ctx, id, owner)
		}
	}()
	started = time.Now()
	prepareErr := a.prepareIdentity(ctx, value)
	recordIdentityPhase(ctx, "bff.begin.prepare", started)
	remove := false
	if prepareErr != nil {
		outcome := classify(prepareErr)
		remove = outcome.status == 401
		if outcome.status == 503 {
			value.Organization = ""
		}
	}
	// 即使后续 UserInfo 失败，也保存已轮换的 refresh token，避免永久丢失有效凭据。
	save, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	started = time.Now()
	commitErr := a.store.commit(save, id, owner, id, value, remove)
	recordIdentityPhase(ctx, "bff.begin.commit", started)
	if commitErr != nil {
		return nil, commitErr
	}
	committed = true
	return value, prepareErr
}

// finishIdentity 重新读取最新会话，只合并安全快照仍匹配的身份结果，不写回旧 SDK。
// SDK/展示资料更新不影响并行读；退出、身份或 CSRF 变化使旧请求失效。
func (a *Runtime) finishIdentity(ctx context.Context, id, nextID string, before, value *session, remove bool) error {
	started := time.Now()
	current, owner, err := a.store.acquire(ctx, id)
	recordIdentityPhase(ctx, "bff.finish.acquire", started)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			a.store.release(ctx, id, owner)
		}
	}()
	if err := mergeIdentityUpdate(current, before, value, a.store.nowTime()); err != nil {
		return err
	}
	current.Organization, current.Revision, current.CSRF = value.Organization, value.Revision, value.CSRF
	save, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	started = time.Now()
	commitErr := a.store.commit(save, id, owner, nextID, current, remove)
	recordIdentityPhase(ctx, "bff.finish.commit", started)
	if commitErr != nil {
		return commitErr
	}
	committed = true
	value.SDK = current.SDK
	value.Profile = current.Profile
	value.ProfileUntil = current.ProfileUntil
	value.Until = current.Until
	value.PolicyVersion = current.PolicyVersion
	value.AuthenticatedAt = current.AuthenticatedAt
	value.IdleUntil = current.IdleUntil
	value.AbsoluteUntil = current.AbsoluteUntil
	return nil
}

// mergeIdentityUpdate adopts only a deadline extension from a snapshot that may
// have run in parallel with an identity read. The current Redis record remains
// authoritative for SDK/profile rotation, logout, CSRF and identity changes.
func mergeIdentityUpdate(current, before, value *session, now time.Time) error {
	changed := func() error {
		return &accessError{status: 409, code: "organization_identity_changed"}
	}
	if current.Subject != before.Subject || current.Organization != before.Organization || current.Revision != before.Revision || current.CSRF != before.CSRF {
		return changed()
	}
	if err := validateSessionSchema(current, now); err != nil {
		return err
	}
	if err := validateSessionSchema(value, now); err != nil {
		return err
	}
	if before.PolicyVersion == 0 {
		if current.PolicyVersion != 0 || value.PolicyVersion != 0 || !current.Until.Equal(before.Until) || !value.Until.Equal(before.Until) {
			return changed()
		}
		return nil
	}
	if before.PolicyVersion != sessionPolicyVersion || current.PolicyVersion != sessionPolicyVersion || value.PolicyVersion != sessionPolicyVersion ||
		!current.AuthenticatedAt.Equal(before.AuthenticatedAt) || !value.AuthenticatedAt.Equal(before.AuthenticatedAt) ||
		!current.AbsoluteUntil.Equal(before.AbsoluteUntil) || !value.AbsoluteUntil.Equal(before.AbsoluteUntil) {
		return changed()
	}
	idle := current.IdleUntil
	if value.IdleUntil.After(idle) {
		idle = value.IdleUntil
	}
	current.IdleUntil = idle
	current.Until = idle
	return nil
}

func (a *Runtime) withIdentitySession(next sessionHandler, authorized ...http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !a.validHost(r) {
			fail(w, r, 403, "host_rejected")
			return
		}
		if len(r.Header.Values("Authorization")) != 0 {
			fail(w, r, 400, "cookie_mode_rejects_bearer")
			return
		}
		if len(r.CookiesNamed(a.config.CookieName)) != 1 {
			fail(w, r, 401, "session_missing_or_ambiguous")
			return
		}
		cookie, err := r.Cookie(a.config.CookieName)
		if err != nil {
			fail(w, r, 401, "session_missing_or_ambiguous")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), _authenticationTimeout)
		defer cancel()
		value, err := a.beginIdentity(ctx, cookie.Value)
		if err != nil {
			outcome := classify(err)
			fail(w, r, outcome.status, "session_unavailable")
			return
		}
		var (
			before  = *value
			outcome = next(r.WithContext(ctx), value)
		)
		if value.Organization != "" && (value.Organization != before.Organization || value.Revision != before.Revision) {
			outcome.rotate = true
		}
		outcome.remove = outcome.remove || outcome.status == 401
		nextID := cookie.Value
		if outcome.rotate && !outcome.remove {
			nextID, err = a.store.opaque()
			if err == nil {
				value.CSRF, err = a.store.opaque()
			}
			if err != nil {
				fail(w, r, 503, "session_entropy_unavailable")
				return
			}
		}
		if err := a.finishIdentity(ctx, cookie.Value, nextID, &before, value, outcome.remove); err != nil {
			failed := classify(err)
			fail(w, r, failed.status, "session_changed_or_unavailable")
			return
		}
		if !outcome.remove {
			if deadline, deadlineErr := sessionDeadline(value, a.store.nowTime()); deadlineErr == nil {
				if data, ok := outcome.data.(map[string]any); ok {
					data["expires_at"] = deadline.Unix()
				}
				if outcome.principal != nil {
					outcome.principal.ExpiresAt = deadline.Unix()
				}
			}
		}
		if outcome.remove {
			a.setCookie(w, a.config.CookieName, "", -1)
		} else if outcome.rotate {
			a.setCookie(w, a.config.CookieName, nextID, sessionCookieMaxAge(value, a.store.nowTime()))
			if data, ok := outcome.data.(map[string]any); ok {
				data["csrf_token"] = value.CSRF
			}
		}
		if outcome.principal != nil && len(authorized) == 1 {
			ctx := a.authorizedContext(r.Context(), nextID, *outcome.principal)
			authorized[0].ServeHTTP(w, r.WithContext(ctx))
			return
		}
		if outcome.redirect != "" {
			http.Redirect(w, r, outcome.redirect, 302)
			return
		}
		if outcome.status >= 400 && !outcome.failureHandled {
			logs.WarnContextw(r.Context(), "logtobff.request.rejected", "status", outcome.status)
		}
		reply(w, r, outcome.status, outcome.data)
	}
}

func (a *Runtime) revalidateIdentity(ctx context.Context, id string, expected Principal, scopes []string) error {
	if len(scopes) > 0 {
		return ErrAuthorizationChanged
	}
	ctx, cancel := context.WithTimeout(ctx, _authenticationTimeout)
	defer cancel()
	value, err := a.beginIdentity(ctx, id)
	if err != nil {
		status := classify(err).status
		if status == 401 || status == 403 || status == 409 {
			return ErrAuthorizationChanged
		}
		return ErrUnavailable
	}
	before := *value
	if value.Subject != expected.UserID || value.Organization != expected.OrganizationID || value.Revision != expected.OrganizationRevision {
		return ErrAuthorizationChanged
	}
	_, _, err = a.currentRequest(ctx, value)
	valid := value.Organization == expected.OrganizationID && value.Revision == expected.OrganizationRevision
	outcome := classify(err)
	if err == nil {
		// 敏感结果路径无法发送新 Cookie，留给下一次 session 请求采纳中央新身份。
		value.Organization, value.Revision = before.Organization, before.Revision
	} else if outcome.status == 503 {
		value.Organization = ""
	}
	if commitErr := a.finishIdentity(ctx, id, id, &before, value, err != nil && outcome.status == 401); commitErr != nil {
		status := classify(commitErr).status
		if status == 401 || status == 403 || status == 409 {
			return ErrAuthorizationChanged
		}
		return ErrUnavailable
	}
	if err != nil {
		if outcome.status == 401 || outcome.status == 403 {
			return ErrAuthorizationChanged
		}
		return ErrUnavailable
	}
	if !valid {
		return ErrAuthorizationChanged
	}
	return nil
}
