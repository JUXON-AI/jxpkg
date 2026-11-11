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
	if authority == nil || cfg.APIResource == "" {
		return nil, errors.New("global BFF requires authority and API resource")
	}
	for _, scope := range cfg.Scopes {
		if strings.HasPrefix(scope, "urn:logto:scope:organization") {
			return nil, errors.New("global BFF rejects organization scopes")
		}
	}
	runtime, err := New(ctx, cfg)
	if err != nil {
		return nil, err
	}
	runtime.globalAuthority = authority
	// GCM 的 AAD 和 Redis key 都绑定模式，即使误复用配置也不能跨模式消费。
	runtime.store.prefix += "global:"
	return runtime, nil
}

// globalCurrent 取 Token 权限与在线权限交集，每个授权判断最多执行一次。
func (a *Runtime) globalCurrent(ctx context.Context, value *session) (profile, *signedClaims, error) {
	if value.SDK == nil {
		return profile{}, nil, &accessError{401, "session_invalid"}
	}
	// 不复用资源 Token，确保刷新授权本身的撤销也在本次请求生效。
	cache := map[string]client.AccessToken{}
	if raw := value.SDK[client.StorageKeyAccessTokenMap]; raw != "" {
		if json.Unmarshal([]byte(raw), &cache) != nil {
			return profile{}, nil, ErrUnavailable
		}
	}
	for key := range cache {
		if key != "@" {
			delete(cache, key)
		}
	}
	encoded, err := json.Marshal(cache)
	if err != nil {
		return profile{}, nil, ErrUnavailable
	}
	value.SDK[client.StorageKeyAccessTokenMap] = string(encoded)
	access, err := a.sdk(ctx, value.SDK).GetAccessTokenWithOptions(client.GetAccessTokenOptions{Resource: a.config.APIResource})
	if err != nil {
		return profile{}, nil, globalSDKFailure(err)
	}
	claims, err := a.verifyGlobal(ctx, access.Token)
	if err != nil {
		return profile{}, nil, err
	}
	if claims.Subject != value.Subject {
		return profile{}, nil, &accessError{401, "global_credential_invalid"}
	}
	decision, err := a.globalAuthority.Permissions(ctx, value.Subject)
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
	return profile{Subject: value.Subject, Username: globalDisplayName(decision.Username), Name: globalDisplayName(decision.Name), Avatar: globalAvatar(decision.Avatar)}, claims, nil
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
	deadline, err := sessionDeadline(value, a.store.nowTime())
	if err != nil {
		return nil, nil, err
	}
	if claims.ExpiresAt.Time.Before(deadline) {
		deadline = claims.ExpiresAt.Time
	}
	epoch := globalEpoch(value.Subject, claims.Scope)
	username := strings.TrimSpace(user.Username)
	if username == "" {
		username = strings.TrimSpace(user.Name)
	}
	permissions := strings.Fields(claims.Scope)
	p := &globalSessionPrincipal{
		Principal:           Principal{Issuer: a.config.Endpoint + "/oidc", UserID: value.Subject, Username: username, OrganizationRevision: epoch, Permissions: permissions, ExpiresAt: deadline.Unix()},
		credentialExpiresAt: claims.ExpiresAt.Time,
	}
	data := map[string]any{"authenticated": true, "user": user, "permissions": permissions, "authority_epoch": epoch, "csrf_token": value.CSRF, "expires_at": deadline.Unix()}
	return data, p, nil
}

func (a *Runtime) globalViewData(ctx context.Context, value *session) (map[string]any, error) {
	data, _, err := a.globalSnapshot(ctx, value)
	return data, err
}

func (a *Runtime) requireGlobal(scopes ...string) gin.HandlerFunc {
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
	if _, _, err := a.globalSnapshot(r.Context(), value); err != nil {
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
	next, err := a.store.create(r.Context(), value, previous)
	if err != nil {
		fail(w, r, 503, "session_store_unavailable")
		return
	}
	a.setCookie(w, a.config.CookieName, next, sessionCookieMaxAge(value, now))
	http.Redirect(w, r, a.config.Origin+tx.ReturnTo, http.StatusFound)
}

func (a *Runtime) renewGlobalSession(r *http.Request, value *session) result {
	if !a.csrfValid(r, value) {
		return problem(403, "csrf_rejected")
	}
	data, principal, err := a.globalSnapshot(r.Context(), value)
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
