package logtobff

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/logto-io/go/v2/client"
	"github.com/redis/go-redis/v9"
)

// GlobalAuthority 在线确认用户、应用准入和当前全局权限；失败必须关闭访问。
// 实现必须绑定启动登记的应用，不能把浏览器输入当作准入或权限。
type GlobalAuthority interface {
	Permissions(context.Context, string) (GlobalAccess, error)
}

// GlobalAccess 将人员准入与业务权限分开；零值明确拒绝，允许无业务角色的白名单成员。
type GlobalAccess struct {
	Allowed     bool
	Permissions []string
	// Username 和 Name 来自本次在线核实的同一用户，只用于显示。
	Username string
	Name     string
	// Avatar 是同一已核实用户的可选 HTTPS 头像，只用于会话显示。
	Avatar string
}

// ErrGlobalAccessDenied 表示权威服务明确拒绝用户或应用准入。
var ErrGlobalAccessDenied = errors.New("global application access denied")

type globalPrincipalKey struct{}

// GlobalPrincipal 是平台管理员主体，不携带或模拟员工组织身份。
type GlobalPrincipal struct {
	Issuer      string   `json:"issuer"`
	UserID      string   `json:"user_id"`
	Username    string   `json:"username"`
	Permissions []string `json:"permissions"`
	Epoch       string   `json:"authority_epoch"`
	ExpiresAt   int64    `json:"expires_at"`
}

// GlobalFromContext 只读取全局浏览器路由验证后发布的主体。
func GlobalFromContext(ctx context.Context) (GlobalPrincipal, bool) {
	p, ok := ctx.Value(globalPrincipalKey{}).(GlobalPrincipal)
	if !ok || p.UserID == "" || p.Epoch == "" || p.ExpiresAt <= time.Now().Unix() {
		return GlobalPrincipal{}, false
	}
	p.Permissions = slices.Clone(p.Permissions)
	return p, true
}

// NewGlobal 复用 OIDC、加密 Redis Session、CSRF 与生命周期，启用独立全局准入模式。
// 该模式不请求组织身份，不向员工上下文发布主体；旧 New 的组织行为不变。
func NewGlobal(ctx context.Context, cfg Config, authority GlobalAuthority) (*Runtime, error) {
	if err := validateGlobalConfig(cfg, authority); err != nil {
		return nil, err
	}
	runtime, err := New(ctx, cfg)
	if err != nil {
		return nil, err
	}
	runtime.configureGlobal(authority)
	return runtime, nil
}

// NewGlobalWithRedis 使用应用初始化的会话 Redis 客户端；应用负责关闭客户端。
func NewGlobalWithRedis(ctx context.Context, cfg Config, authority GlobalAuthority, redisClient *redis.Client) (*Runtime, error) {
	if err := validateGlobalConfig(cfg, authority); err != nil {
		return nil, err
	}
	runtime, err := NewWithRedis(ctx, cfg, redisClient)
	if err != nil {
		return nil, err
	}
	runtime.configureGlobal(authority)
	return runtime, nil
}

func validateGlobalConfig(cfg Config, authority GlobalAuthority) error {
	if authority == nil || cfg.APIResource == "" {
		return errors.New("global BFF requires authority and API resource")
	}
	for _, scope := range cfg.Scopes {
		if strings.HasPrefix(scope, "urn:logto:scope:organization") {
			return errors.New("global BFF rejects organization scopes")
		}
	}
	return nil
}

func (a *Runtime) configureGlobal(authority GlobalAuthority) {
	a.globalAuthority = authority
	// GCM 的 AAD 和 Redis key 都绑定模式，即使误复用配置也不能跨模式消费。
	a.store.prefix += "global:"
}

// globalCurrent 取 Token 权限与在线权限交集，每个授权判断最多执行一次。
func (a *Runtime) globalCurrent(ctx context.Context, value *session) (profile, *signedClaims, error) {
	raw, err := a.globalResourceToken(ctx, value)
	if err != nil {
		return profile{}, nil, err
	}
	return a.globalDecision(ctx, value.Subject, raw)
}

func (a *Runtime) globalResourceToken(ctx context.Context, value *session) (string, error) {
	if value.SDK == nil {
		return "", &accessError{401, "session_invalid"}
	}
	// 不复用资源 Token，确保刷新授权本身的撤销也在本次请求生效。
	cache := map[string]client.AccessToken{}
	if raw := value.SDK[client.StorageKeyAccessTokenMap]; raw != "" {
		if json.Unmarshal([]byte(raw), &cache) != nil {
			return "", ErrUnavailable
		}
	}
	for key := range cache {
		if key != "@" {
			delete(cache, key)
		}
	}
	encoded, err := json.Marshal(cache)
	if err != nil {
		return "", ErrUnavailable
	}
	value.SDK[client.StorageKeyAccessTokenMap] = string(encoded)
	started := time.Now()
	access, err := a.sdk(ctx, value.SDK).GetAccessTokenWithOptions(client.GetAccessTokenOptions{Resource: a.config.APIResource})
	recordIdentityPhase(ctx, "bff.global.resource_token", started)
	if err != nil {
		return "", globalSDKFailure(err)
	}
	return access.Token, nil
}

func (a *Runtime) globalDecision(ctx context.Context, subject, raw string) (profile, *signedClaims, error) {
	claims, err := a.verifyGlobal(ctx, raw)
	if err != nil {
		return profile{}, nil, err
	}
	if claims.Subject != subject {
		return profile{}, nil, &accessError{401, "global_credential_invalid"}
	}
	started := time.Now()
	decision, err := a.globalAuthority.Permissions(ctx, subject)
	recordIdentityPhase(ctx, "bff.global.permissions", started)
	if errors.Is(err, ErrGlobalAccessDenied) {
		return profile{}, nil, &accessError{403, "application_access_denied"}
	}
	if err != nil {
		return profile{}, nil, err
	}
	if !decision.Allowed {
		return profile{}, nil, &accessError{403, "application_access_denied"}
	}
	permissions := decision.Permissions
	allowed := make(map[string]bool, len(permissions))
	for _, permission := range permissions {
		allowed[permission] = true
	}
	effective := make([]string, 0, len(permissions))
	for _, permission := range strings.Fields(claims.Scope) {
		if allowed[permission] && !slices.Contains(effective, permission) {
			effective = append(effective, permission)
		}
	}
	slices.Sort(effective)
	claims.Scope = strings.Join(effective, " ")
	return profile{Subject: subject, Username: globalDisplayName(decision.Username), Name: globalDisplayName(decision.Name), Avatar: globalAvatar(decision.Avatar)}, claims, nil
}

func globalAvatar(value string) string {
	if len(value) > 4096 || !utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return ""
	}
	return u.String()
}

// globalDisplayName 的异常显示值只被省略，不改变已核实的准入和权限。
func globalDisplayName(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 512 || !utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) {
		return ""
	}
	return value
}

// verifyGlobal 不允许组织 Token 降级进入平台权限模式。
func (a *Runtime) verifyGlobal(ctx context.Context, raw string) (*signedClaims, error) {
	claims, err := a.verifyClaims(ctx, raw, "", a.config.ClientID, true)
	if errors.Is(err, ErrUnavailable) {
		return nil, err
	}
	if err != nil {
		return nil, &accessError{401, "global_credential_invalid"}
	}
	return claims, nil
}

func globalSDKFailure(err error) error {
	result := sdkFailure(err)
	var denied *accessError
	if errors.As(result, &denied) && denied.status == 403 {
		return &accessError{403, "application_access_denied"}
	}
	return result
}

func globalEpoch(subject, scope string) string {
	digest := sha256.Sum256([]byte(subject + "\x00" + scope))
	return hex.EncodeToString(digest[:])
}

// globalSessionPrincipal keeps the token deadline out of the public employee principal.
type globalSessionPrincipal struct {
	Principal
	credentialExpiresAt time.Time
}

func (a *Runtime) globalSnapshot(ctx context.Context, value *session) (map[string]any, *globalSessionPrincipal, error) {
	user, claims, err := a.globalCurrent(ctx, value)
	if err != nil {
		return nil, nil, err
	}
	return a.globalProjection(value, user, claims.Scope, claims.ExpiresAt.Time)
}

func (a *Runtime) globalProjection(value *session, user profile, scope string, tokenUntil time.Time) (map[string]any, *globalSessionPrincipal, error) {
	deadline, err := sessionDeadline(value, a.store.nowTime())
	if err != nil {
		return nil, nil, err
	}
	if tokenUntil.Before(deadline) {
		deadline = tokenUntil
	}
	epoch := globalEpoch(value.Subject, scope)
	username := strings.TrimSpace(user.Username)
	if username == "" {
		username = strings.TrimSpace(user.Name)
	}
	permissions := strings.Fields(scope)
	p := &globalSessionPrincipal{
		Principal:           Principal{Issuer: a.config.Endpoint + "/oidc", UserID: value.Subject, Username: username, OrganizationRevision: epoch, Permissions: permissions, ExpiresAt: deadline.Unix()},
		credentialExpiresAt: tokenUntil,
	}
	data := map[string]any{"authenticated": true, "user": user, "permissions": permissions, "authority_epoch": epoch, "csrf_token": value.CSRF, "expires_at": deadline.Unix()}
	return data, p, nil
}

func (a *Runtime) globalViewData(ctx context.Context, value *session) (map[string]any, error) {
	data, _, err := a.globalSnapshot(ctx, value)
	return data, err
}

func (a *Runtime) requireGlobal(scopes ...string) gin.HandlerFunc {
	if a.config.GlobalReadFastPath {
		return a.globalFastRequire(true, scopes...)
	}
	return func(c *gin.Context) {
		called := false
		a.withSession(func(r *http.Request, s *session) result {
			if !a.csrfValid(r, s) {
				return problem(403, "csrf_rejected")
			}
			_, principal, err := a.globalSnapshot(r.Context(), s)
			if err != nil {
				return classify(err)
			}
			if len(r.Header.Values("X-Authority-Epoch")) != 1 || r.Header.Get("X-Authority-Epoch") != principal.OrganizationRevision {
				return problem(409, "authority_changed")
			}
			for _, scope := range scopes {
				if scope == "" || !slices.Contains(principal.Permissions, scope) {
					return problem(403, "insufficient_scope")
				}
			}
			return result{status: 200, principal: &principal.Principal}
		}, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { called = true; c.Request = r; c.Next() }))(c.Writer, c.Request)
		if !called {
			c.Abort()
		}
	}
}

func (a *Runtime) finishGlobalLogin(w http.ResponseWriter, r *http.Request, tx transaction, subject string) {
	csrf, err := a.store.opaque()
	if err != nil {
		fail(w, r, 503, "session_entropy_unavailable")
		return
	}
	now := a.store.nowTime()
	value := &session{SDK: tx.SDK, Subject: subject, CSRF: csrf, Until: now.Add(sessionIdleLifetime), PolicyVersion: sessionPolicyVersion, AuthenticatedAt: now, IdleUntil: now.Add(sessionIdleLifetime), AbsoluteUntil: now.Add(sessionAbsoluteLifetime)}
	var started time.Time
	if a.config.GlobalReadFastPath {
		started, err = a.store.db.Time(r.Context()).Result()
		if err != nil {
			fail(w, r, 503, "session_store_unavailable")
			return
		}
	}
	user, claims, err := a.globalCurrent(r.Context(), value)
	if err != nil {
		outcome := classify(err)
		code := "global_identity_unavailable"
		var denied *accessError
		if errors.As(err, &denied) {
			code = denied.code
		}
		fail(w, r, outcome.status, code)
		return
	}
	previous := ""
	if cookies := r.CookiesNamed(a.config.CookieName); len(cookies) > 1 {
		fail(w, r, 400, "session_ambiguous")
		return
	} else if len(cookies) == 1 {
		previous = cookies[0].Value
	}
	if a.config.GlobalReadFastPath {
		marker, markerErr := a.store.opaque()
		if markerErr != nil {
			fail(w, r, 503, "session_entropy_unavailable")
			return
		}
		value.GlobalRead = &globalReadSnapshot{Marker: marker, CheckedAt: now, User: user, Scope: claims.Scope, TokenUntil: claims.ExpiresAt.Time}
	}
	next, err := a.store.create(r.Context(), value, previous)
	if err != nil {
		fail(w, r, 503, "session_store_unavailable")
		return
	}
	if value.GlobalRead != nil {
		// A failed marker write leaves the first read on the fail-closed cold path.
		_ = a.publishGlobalReadMarker(r.Context(), next, value.GlobalRead.Marker, started)
	}
	a.setCookie(w, a.config.CookieName, next, sessionCookieMaxAge(value, now))
	http.Redirect(w, r, a.config.Origin+tx.ReturnTo, http.StatusFound)
}

func (a *Runtime) renewGlobalSession(r *http.Request, value *session) result {
	if !a.csrfValid(r, value) {
		return problem(403, "csrf_rejected")
	}
	return a.renewGlobalSessionWithProof(r, value, nil)
}

func (a *Runtime) renewGlobalSessionWithProof(r *http.Request, value *session, proof *globalReadSnapshot) result {
	var data map[string]any
	var principal *globalSessionPrincipal
	var err error
	if proof != nil {
		if !a.store.nowTime().Before(proof.CheckedAt.Add(globalReadLifetime)) {
			return problem(409, "authority_refresh_required")
		}
		data, principal, err = a.globalProjection(value, proof.User, proof.Scope, proof.TokenUntil)
	} else {
		data, principal, err = a.globalSnapshot(r.Context(), value)
	}
	if err != nil {
		return classify(err)
	}
	if len(r.Header.Values("X-Authority-Epoch")) != 1 || r.Header.Get("X-Authority-Epoch") != principal.OrganizationRevision {
		return problem(409, "authority_changed")
	}
	value.IdleUntil = nextSessionIdle(a.store.nowTime(), value.AbsoluteUntil)
	value.Until = value.IdleUntil
	deadline, err := sessionDeadline(value, a.store.nowTime())
	if err != nil {
		return classify(err)
	}
	if principal.credentialExpiresAt.Before(deadline) {
		deadline = principal.credentialExpiresAt
	}
	data["expires_at"] = deadline.Unix()
	return result{status: 200, data: data}
}

// globalSessionView 避免会话投影重复获取相同的用户和权限。
func (a *Runtime) globalSessionView(r *http.Request, value *session) result {
	data, err := a.globalViewData(r.Context(), value)
	if err != nil {
		return classify(err)
	}
	return result{status: 200, data: data}
}
