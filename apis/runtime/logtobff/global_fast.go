package logtobff

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

const (
	globalReadLifetime   = 15 * time.Second
	globalRefreshLease   = 30 * time.Second
	globalRefreshBackoff = time.Second
)

type globalReadSnapshot struct {
	Marker     string
	CheckedAt  time.Time
	User       profile
	Scope      string
	TokenUntil time.Time
}

// RequireGlobalRead is for read-only routes. It accepts only an opted-in global
// browser session and retains the same CSRF, authority epoch and scope checks.
func (a *Runtime) RequireGlobalRead(scopes ...string) gin.HandlerFunc {
	if a.globalAuthority == nil || !a.config.GlobalReadFastPath {
		// A disabled fast path preserves online authorization for global routes.
		if a.globalAuthority != nil {
			return a.requireGlobal(scopes...)
		}
		return func(c *gin.Context) {
			fail(c.Writer, c.Request, http.StatusForbidden, "global_session_required")
			c.Abort()
		}
	}
	return a.globalFastRequire(false, scopes...)
}

func (s *store) readGlobal(ctx context.Context, id string) (*session, error) {
	if !_opaquePattern.MatchString(id) {
		return nil, _errMissing
	}
	key := s.prefix + "s:" + id
	rows, err := s.db.MGet(ctx, key, s.prefix+"lock:read-valid:"+id).Result()
	if err != nil {
		return nil, globalStoreFailure(err, "session_store_unavailable")
	}
	raw, ok := rows[0].(string)
	if !ok {
		return nil, _errMissing
	}
	var value session
	if err := s.open(key, []byte(raw), &value); err != nil {
		return nil, err
	}
	if _, err := sessionDeadline(&value, s.nowTime()); err != nil {
		return nil, err
	}
	if value.GlobalRead != nil && (value.GlobalRead.Marker == "" || rows[1] != value.GlobalRead.Marker) {
		value.GlobalRead = nil
	}
	return &value, nil
}

func (a *Runtime) usableGlobalRead(s *session) bool {
	p, now := s.GlobalRead, a.store.nowTime()
	return p != nil && p.User.Subject == s.Subject && s.Subject != "" &&
		!now.Before(p.CheckedAt) && now.Before(p.CheckedAt.Add(globalReadLifetime)) &&
		now.Unix() < p.TokenUntil.Unix()
}

func (a *Runtime) globalFastRequest(r *http.Request, csrf bool) (string, *session, error) {
	if !a.validHost(r) {
		return "", nil, &accessError{403, "host_rejected"}
	}
	if len(r.Header.Values("Authorization")) != 0 {
		return "", nil, &accessError{400, "cookie_mode_rejects_bearer"}
	}
	cookies := r.CookiesNamed(a.config.CookieName)
	if len(cookies) != 1 {
		return "", nil, &accessError{401, "session_missing_or_ambiguous"}
	}
	id := cookies[0].Value
	s, err := a.store.readGlobal(r.Context(), id)
	if err != nil {
		return "", nil, err
	}
	if csrf && !a.csrfValid(r, s) {
		return "", nil, &accessError{403, "csrf_rejected"}
	}
	return id, s, nil
}

func globalRequireScopes(r *http.Request, p *globalSessionPrincipal, scopes []string) result {
	if len(r.Header.Values("X-Authority-Epoch")) != 1 || r.Header.Get("X-Authority-Epoch") != p.OrganizationRevision {
		return problem(409, "authority_changed")
	}
	for _, scope := range scopes {
		if scope == "" || !slices.Contains(p.Permissions, scope) {
			return problem(403, "insufficient_scope")
		}
	}
	return result{status: 200, principal: &p.Principal}
}

// globalFastRequire checks the signed session from Redis. Writes always use a
// fresh grant and permission decision, never the short-lived read snapshot.
func (a *Runtime) globalFastRequire(live bool, scopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		original := c.Request
		ctx, cancel := context.WithTimeout(original.Context(), _authenticationTimeout)
		defer cancel()
		r := original.WithContext(ctx)
		c.Header("Cache-Control", "no-store")
		id, s, err := a.globalFastRequest(r, true)
		if err == nil && live {
			s, err = a.checkGlobalLive(ctx, id)
		} else if err == nil && !a.usableGlobalRead(s) {
			s, err = a.refreshGlobalRead(ctx, id)
		}
		out := classify(err)
		if err == nil {
			if !a.csrfValid(r, s) {
				out = problem(403, "csrf_rejected")
			} else if !a.usableGlobalRead(s) {
				out = problem(503, "global_authority_unavailable")
			} else {
				_, p, projectionErr := a.globalProjection(s, s.GlobalRead.User, s.GlobalRead.Scope, s.GlobalRead.TokenUntil)
				if projectionErr != nil {
					out = classify(projectionErr)
				} else {
					out = globalRequireScopes(r, p, scopes)
				}
			}
		}
		if out.principal == nil {
			a.replyGlobalFast(c.Writer, r, out)
			c.Abort()
			return
		}
		c.Request = original.WithContext(a.authorizedContext(original.Context(), id, *out.principal))
		c.Next()
	}
}

// checkGlobalLive confines refresh-token rotation to the existing Redis lease.
// Permission I/O runs outside it. A final read fences logout/session replacement.
func (a *Runtime) checkGlobalLive(ctx context.Context, id string) (*session, error) {
	s, owner, err := a.store.acquire(ctx, id)
	if err != nil {
		return nil, globalStoreFailure(err, "session_store_unavailable")
	}
	started := a.store.nowTime()
	generation, err := a.store.opaque()
	if err != nil {
		a.store.release(ctx, id, owner)
		return nil, err
	}
	raw, refreshErr := a.globalResourceToken(ctx, s)
	s.GlobalGeneration = generation
	save, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	var denied *accessError
	remove := errors.As(refreshErr, &denied) && denied.status == http.StatusUnauthorized
	err = a.store.commit(save, id, owner, id, s, remove)
	cancel()
	if err != nil {
		a.store.release(ctx, id, owner)
		return nil, globalStoreFailure(err, "session_commit_failed")
	}
	if refreshErr != nil {
		return nil, refreshErr
	}

	user, claims, err := a.globalDecision(ctx, s.Subject, raw)
	if err != nil {
		var denied *accessError
		if errors.As(err, &denied) && denied.status == http.StatusUnauthorized {
			if err := a.dropInvalidGlobal(ctx, id, s); err != nil {
				return nil, err
			}
		} else if errors.As(err, &denied) && denied.status == http.StatusForbidden {
			if invalidateErr := a.invalidateGlobalRead(ctx, id, s.GlobalRead); invalidateErr != nil {
				return nil, invalidateErr
			}
		}
		return nil, err
	}
	latest, err := a.store.readGlobal(ctx, id)
	if err != nil {
		return nil, err
	}
	if latest.Subject != s.Subject || latest.CSRF != s.CSRF {
		return nil, _errMissing
	}
	if s.GlobalRead != nil && s.GlobalRead.Scope != claims.Scope {
		if err := a.invalidateGlobalRead(ctx, id, s.GlobalRead); err != nil {
			return nil, err
		}
	}
	latest.GlobalRead = &globalReadSnapshot{CheckedAt: started, User: user, Scope: claims.Scope, TokenUntil: claims.ExpiresAt.Time}
	if !a.usableGlobalRead(latest) {
		return nil, ErrUnavailable
	}
	return latest, nil
}

// refreshGlobalRead shares one cold refresh across replicas without involving
// the refresh lease at all on the hot path. Only the elected owner publishes.
func (a *Runtime) refreshGlobalRead(ctx context.Context, id string) (*session, error) {
	lock := a.store.prefix + "lock:read:" + id
	backoff := a.store.prefix + "lock:read-backoff:" + id
	owner, err := a.store.opaque()
	if err != nil {
		return nil, err
	}
	for {
		s, err := a.store.readGlobal(ctx, id)
		if err != nil || a.usableGlobalRead(s) {
			return s, err
		}
		if err := a.globalRefreshFailure(ctx, backoff); err != nil {
			return nil, err
		}
		won, err := a.store.db.SetNX(ctx, lock, owner, globalRefreshLease).Result()
		if err != nil {
			return nil, globalStoreFailure(err, "session_store_unavailable")
		}
		if won {
			return a.refreshGlobalReadOwned(ctx, id, owner, backoff)
		}
		timer := time.NewTimer(80 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (a *Runtime) refreshGlobalReadOwned(ctx context.Context, id, readOwner, backoff string) (*session, error) {
	defer a.store.release(ctx, "read:"+id, readOwner)
	s, err := a.store.readGlobal(ctx, id)
	if err != nil || a.usableGlobalRead(s) {
		return s, err
	}
	if err := a.globalRefreshFailure(ctx, backoff); err != nil {
		return nil, err
	}
	started, err := a.store.db.Time(ctx).Result()
	if err != nil {
		return nil, globalStoreFailure(err, "session_store_unavailable")
	}
	verified, err := a.checkGlobalLive(ctx, id)
	if err != nil {
		status := classify(err).status
		if status == http.StatusServiceUnavailable || status == http.StatusForbidden {
			save, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			_ = a.store.db.Set(save, backoff, strconv.Itoa(status), globalRefreshBackoff).Err()
			cancel()
		}
		return nil, err
	}
	latest, owner, err := a.store.acquire(ctx, id)
	if err != nil {
		return nil, globalStoreFailure(err, "session_store_unavailable")
	}
	if latest.Subject != verified.Subject || latest.CSRF != verified.CSRF || !a.usableGlobalRead(verified) {
		a.store.release(ctx, id, owner)
		return nil, ErrUnavailable
	}
	latest.GlobalRead = verified.GlobalRead
	latest.GlobalRead.Marker = readOwner
	err = a.store.commit(ctx, id, owner, id, latest, false)
	if err != nil {
		a.store.release(ctx, id, owner)
		return nil, globalStoreFailure(err, "session_commit_failed")
	}
	if err := a.publishGlobalReadMarker(ctx, id, readOwner, started); err != nil {
		return nil, globalStoreFailure(err, "session_commit_failed")
	}
	return a.store.readGlobal(ctx, id)
}

// Use Redis TIME and PXAT so a slower replica cannot extend the revocation window.
func (a *Runtime) publishGlobalReadMarker(ctx context.Context, id, marker string, started time.Time) error {
	return a.store.db.Do(ctx, "SET", a.store.prefix+"lock:read-valid:"+id, marker,
		"PXAT", started.Add(globalReadLifetime).UnixMilli()).Err()
}

func (a *Runtime) globalRefreshFailure(ctx context.Context, key string) error {
	status, err := a.store.db.Get(ctx, key).Int()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	if err != nil {
		return globalStoreFailure(err, "session_store_unavailable")
	}
	if status == http.StatusForbidden {
		return &accessError{403, "application_access_denied"}
	}
	return ErrUnavailable
}

func globalStoreFailure(err error, code string) error {
	if err == nil || errors.Is(err, _errMissing) || errors.Is(err, _errInvalid) || errors.Is(err, _errBusy) {
		return err
	}
	return &accessError{503, code}
}

// Invalidate only the marker observed by this decision, never a replacement
// published by another replica.
func (a *Runtime) invalidateGlobalRead(ctx context.Context, id string, previous *globalReadSnapshot) error {
	if previous == nil || previous.Marker == "" {
		return nil
	}
	err := a.store.db.Eval(ctx, `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) end return 0`,
		[]string{a.store.prefix + "lock:read-valid:" + id}, previous.Marker).Err()
	return globalStoreFailure(err, "session_store_unavailable")
}

func (a *Runtime) dropInvalidGlobal(ctx context.Context, id string, previous *session) error {
	s, owner, err := a.store.acquire(ctx, id)
	if err != nil {
		return globalStoreFailure(err, "session_store_unavailable")
	}
	defer a.store.release(ctx, id, owner)
	if s.Subject != previous.Subject || s.CSRF != previous.CSRF {
		return _errMissing
	}
	if s.GlobalGeneration != previous.GlobalGeneration || !maps.Equal(s.SDK, previous.SDK) {
		return &accessError{409, "authority_changed"}
	}
	return globalStoreFailure(a.store.commit(ctx, id, owner, id, s, true), "session_commit_failed")
}

func (a *Runtime) replyGlobalFast(w http.ResponseWriter, r *http.Request, out result) {
	if out.status == http.StatusUnauthorized && len(r.CookiesNamed(a.config.CookieName)) == 1 {
		a.setCookie(w, a.config.CookieName, "", -1)
	}
	if body, ok := out.data.(map[string]string); ok && out.status >= 400 {
		fail(w, r, out.status, body["error"])
		return
	}
	reply(w, r, out.status, out.data)
}

func (a *Runtime) globalFastSessionView(w http.ResponseWriter, r *http.Request) {
	id, s, err := a.globalFastRequest(r, false)
	if err == nil && !a.usableGlobalRead(s) {
		s, err = a.refreshGlobalRead(r.Context(), id)
	}
	if err == nil && !a.usableGlobalRead(s) {
		err = ErrUnavailable
	}
	if err == nil {
		data, _, projectionErr := a.globalProjection(s, s.GlobalRead.User, s.GlobalRead.Scope, s.GlobalRead.TokenUntil)
		if projectionErr == nil {
			reply(w, r, http.StatusOK, data)
			return
		}
		err = projectionErr
	}
	out := classify(err)
	a.replyGlobalFast(w, r, out)
}

// globalFastRenew does online refresh outside the ordinary session lease before
// the short, fenced idle extension. It never slides a session on GET.
func (a *Runtime) globalFastRenew(w http.ResponseWriter, r *http.Request) {
	id, s, err := a.globalFastRequest(r, true)
	if err == nil {
		s, err = a.checkGlobalLive(r.Context(), id)
	}
	if err != nil {
		a.replyGlobalFast(w, r, classify(err))
		return
	}
	proof := s.GlobalRead
	a.withSession(func(r *http.Request, current *session) result {
		if current.Subject != s.Subject || current.CSRF != s.CSRF {
			return problem(401, "session_expired")
		}
		return a.renewGlobalSessionWithProof(r, current, proof)
	})(w, r)
}
