package logtobff

import (
	"net/http"
	"time"
)

// renewSession turns a trusted browser activity into an idle-deadline extension.
// The fixed authenticated-at absolute deadline is never replaced, and missing or
// changed authority fails closed before Redis can persist a later idle value.
func (a *Runtime) renewSession(r *http.Request, value *session) result {
	if !a.csrfValid(r, value) {
		return problem(http.StatusForbidden, "csrf_rejected")
	}
	if len(r.Header.Values("X-Organization-ID")) != 1 || len(r.Header.Values("X-Organization-Revision")) != 1 ||
		r.Header.Get("X-Organization-ID") != value.Organization || r.Header.Get("X-Organization-Revision") != value.Revision {
		return problem(http.StatusConflict, "organization_identity_changed")
	}
	if value.PolicyVersion != sessionPolicyVersion {
		return problem(http.StatusConflict, "session_renewal_unsupported")
	}

	organization, revision := value.Organization, value.Revision
	user, rows, err := a.currentRequest(r.Context(), value)
	if err != nil {
		value.Organization, value.Revision = organization, revision
		return classify(err)
	}
	if value.Organization != organization || value.Revision != revision {
		value.Organization, value.Revision = organization, revision
		return problem(http.StatusConflict, "organization_identity_changed")
	}
	// Resource mode holds this lease across the online check. Recheck the
	// acquired snapshot so Redis latency cannot turn an idle expiry into renewal.
	if a.config.APIResource != "" {
		if _, err := sessionDeadline(value, a.store.nowTime()); err != nil {
			return classify(err)
		}
	}

	originalIdle, originalUntil := value.IdleUntil, value.Until
	now := a.store.nowTime()
	value.IdleUntil = nextSessionIdle(now, value.AbsoluteUntil)
	value.Until = value.IdleUntil
	data, err := a.sessionViewData(r.Context(), value, user, rows)
	if err != nil {
		value.IdleUntil, value.Until = originalIdle, originalUntil
		return classify(err)
	}
	return result{status: http.StatusOK, data: data}
}

// sessionCookieDeadline is intentionally the absolute deadline. The browser
// cookie may outlive idle so a later touch can extend Redis state without a
// same-ID Set-Cookie race; Redis remains the authorization authority.
func sessionCookieDeadline(value *session) (time.Time, error) {
	if err := validateSessionSchema(value, value.AuthenticatedAt); err != nil {
		return time.Time{}, err
	}
	return value.AbsoluteUntil, nil
}
