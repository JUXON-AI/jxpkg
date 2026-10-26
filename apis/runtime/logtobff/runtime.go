// Package logtobff 提供直接接入 Logto 的 OIDC 和业务浏览器会话，不依赖旧 Account resolver。
package logtobff

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/JUXON-AI/jxpkg/requestid"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
)

var _opaquePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var _orgPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

const _authenticationTimeout = 20 * time.Second

type principalKey struct{}

// Config 由应用启动时显式提供；密钥不得返回浏览器或写入日志。
type Config struct {
	// Endpoint 是启动登记的 Logto origin，发行者固定为其 /oidc。
	Endpoint string `json:"endpoint"`
	// Origin 是浏览器的固定产品 origin，用于 Host、CSRF 和回调校验。
	Origin string `json:"origin"`
	// ClientID 标识本产品的传统 Web 应用。
	ClientID string `json:"clientId"`
	// ClientSecret 仅供服务器调用身份服务，不得传给浏览器。
	ClientSecret string `json:"clientSecret"`
	// APIResource 非空时验证组织资源 Token；为空时只提供 App 准入身份，不发布部门或角色权限。
	APIResource string `json:"apiResource"`
	// Scopes 请求 OIDC 资料及可选资源 scope，本参数本身不授予业务权限。
	Scopes []string `json:"scopes"`
	// CookieName 是本产品独立的 Host-only 会话 Cookie 名。
	CookieName string `json:"cookieName"`
	// Namespace 隔离本产品的 Redis 短期认证数据。
	Namespace string `json:"namespace"`
	// RedisAddress 来自启动配置，不接受请求覆盖。
	RedisAddress string `json:"redisAddress"`
	// RedisPassword 仅用于本运行时持有的 Redis 连接。
	RedisPassword string `json:"redisPassword"`
	// SessionKey 是 32 字节 base64url 会话加密密钥。
	SessionKey string `json:"sessionKey"`
	// AllowLocalHTTP 只允许显式 local 配置中的环回地址；生产配置默认 HTTPS。
	AllowLocalHTTP bool `json:"allowLocalHttp"`
	// Environment 为 local 时才允许启用环回 HTTP。
	Environment string `json:"environment"`
}

// Principal 是本次请求在线确认的身份快照；资源模式另行验证组织 API Token。
type Principal struct {
	// Issuer 来自经过验证的固定发行者。
	Issuer string `json:"issuer"`
	// UserID 是签名 Token 中的全局用户标识。
	UserID string `json:"user_id"`
	// OrganizationID 是已确认有效且获准进入此 App 的组织身份。
	OrganizationID string `json:"organization_id"`
	// OrganizationRevision binds operations to the identity snapshot rendered by the caller.
	OrganizationRevision string `json:"organization_revision"`
	// DepartmentIDs 是组织资源 Token 发布的部门范围；纯会话准入模式不提供此字段。
	DepartmentIDs []string `json:"department_ids"`
	// PrimaryDepartmentID 是资源模式组织 Token 发布的可选主部门。
	PrimaryDepartmentID *string `json:"primary_department_id"`
	// Permissions 是组织资源 Token 的权限；纯会话准入模式始终为空。
	Permissions []string `json:"permissions"`
	// ExpiresAt 是身份快照的到期秒；纯会话模式使用 Session 到期，资源模式使用 Token 到期。
	ExpiresAt int64 `json:"expires_at"`
}

// FromContext 仅从本包发布的请求上下文读取可信主体，不能使用客户端 JSON 代替。
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	if !ok || p.UserID == "" || p.OrganizationID == "" || p.ExpiresAt <= time.Now().Unix() {
		return Principal{}, false
	}
	p.Permissions = slices.Clone(p.Permissions)
	p.DepartmentIDs = slices.Clone(p.DepartmentIDs)
	if p.PrimaryDepartmentID != nil {
		primary := *p.PrimaryDepartmentID
		p.PrimaryDepartmentID = &primary
	}
	return p, true
}

type signatureVerifier interface {
	VerifySignature(context.Context, string) ([]byte, error)
}

// Runtime 拥有一个产品的独立 Redis 会话命名空间及 OIDC 客户端。
type Runtime struct {
	config   Config
	verifier *oidc.IDTokenVerifier
	keys     signatureVerifier
	http     *http.Client
	store    *store
}

type boundedTransport struct {
	base   http.RoundTripper
	origin string
}

func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme+"://"+r.URL.Host != t.origin {
		return nil, errors.New("unregistered identity endpoint")
	}
	clone := r.Clone(r.Context())
	if id := requestid.FromContext(r.Context()); id != "" {
		clone.Header.Set("X-Request-Id", id)
	}
	response, err := t.base.RoundTrip(clone)
	if err == nil {
		response.Body = http.MaxBytesReader(nil, response.Body, 1<<20)
	}
	return response, err
}

func validOrigin(raw string, local bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.String() != raw {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return local && u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback())
}

// New 验证固定配置并连接身份服务和 Redis；调用者负责 Close，无导入期副作用。
func New(ctx context.Context, cfg Config) (*Runtime, error) {
	cfg.Scopes = slices.Clone(cfg.Scopes)
	local := cfg.Environment == "local" && cfg.AllowLocalHTTP
	if (cfg.AllowLocalHTTP && !local) || !validOrigin(cfg.Endpoint, local) || !validOrigin(cfg.Origin, local) || cfg.ClientID == "" || cfg.ClientSecret == "" || len(cfg.Scopes) == 0 || !_orgPattern.MatchString(cfg.Namespace) || !_orgPattern.MatchString(cfg.CookieName) || (strings.HasPrefix(cfg.CookieName, "__Host-") || strings.HasPrefix(cfg.CookieName, "__Secure-")) && !strings.HasPrefix(cfg.Origin, "https:") || cfg.RedisAddress == "" {
		return nil, errors.New("invalid Logto BFF configuration")
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &discoveryTransport{base: boundedTransport{http.DefaultTransport, cfg.Endpoint}, endpoint: cfg.Endpoint + "/oidc/.well-known/openid-configuration"}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	discovery, cancel := context.WithTimeout(oidc.ClientContext(ctx, client), 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(discovery, cfg.Endpoint+"/oidc")
	if err != nil {
		return nil, errors.New("Logto discovery unavailable")
	}
	var metadata struct {
		JWKS string `json:"jwks_uri"`
	}
	if provider.Claims(&metadata) != nil || !strings.HasPrefix(metadata.JWKS, cfg.Endpoint+"/") || !strings.HasPrefix(provider.Endpoint().AuthURL, cfg.Endpoint+"/") || !strings.HasPrefix(provider.Endpoint().TokenURL, cfg.Endpoint+"/") {
		return nil, errors.New("Logto discovery invalid")
	}
	storage, err := newStore(cfg.RedisAddress, cfg.RedisPassword, cfg.SessionKey, cfg.Namespace+":")
	if err != nil {
		return nil, errors.New("session storage configuration invalid")
	}
	if storage.db.Ping(discovery).Err() != nil {
		_ = storage.db.Close()
		return nil, errors.New("session store unavailable")
	}

	return &Runtime{config: cfg, http: client, verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}), keys: oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), metadata.JWKS), store: storage}, nil
}

// Close 释放本运行时持有的 Redis 连接。
func (a *Runtime) Close() error { return a.store.db.Close() }

// Handler 提供固定 /auth 路由；GET session 只报告当前状态，可信的 POST
// session 才滑动 idle，登录后仅返回经过校验的本站路径。
func (a *Runtime) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", a.login)
	mux.HandleFunc("GET /auth/auto-login", a.autoLogin)
	mux.HandleFunc("GET /auth/callback", a.callback)
	mux.HandleFunc("GET /auth/session", a.withSession(a.sessionView))
	mux.HandleFunc("POST /auth/session", a.withSession(a.renewSession))
	mux.HandleFunc("GET /auth/switch-organization", a.login)
	mux.HandleFunc("POST /auth/logout", a.withSession(a.logout))
	mux.HandleFunc("GET /auth/account-center", a.withSession(a.accountCenter))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if !a.validHost(r) {
			fail(w, r, 403, "host_rejected")
			return
		}
		if len(r.Header.Values("Authorization")) != 0 {
			fail(w, r, 400, "cookie_mode_rejects_bearer")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), _authenticationTimeout)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (a *Runtime) validHost(r *http.Request) bool {
	u, _ := url.Parse(a.config.Origin)
	return r.Host == u.Host
}
func (a *Runtime) setCookie(w http.ResponseWriter, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(a.config.Origin, "https:"), SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func reply(w http.ResponseWriter, r *http.Request, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if json.NewEncoder(w).Encode(data) != nil {
		logs.WarnContext(r.Context(), "logtobff.response.write_failed")
	}
}
func fail(w http.ResponseWriter, r *http.Request, status int, code string) {
	logs.WarnContextw(r.Context(), "logtobff.request.rejected", "status", status, "reason", code)
	reply(w, r, status, map[string]string{"error": code})
}

type result struct {
	status         int
	data           any
	rotate, remove bool
	redirect       string
	principal      *Principal
	// failureHandled means the handler already recorded its final rejection reason.
	failureHandled bool
}
type sessionHandler func(*http.Request, *session) result

func problem(status int, code string) result {
	return result{status: status, data: map[string]string{"error": code}}
}
func classify(err error) result {
	if errors.Is(err, _errMissing) {
		return problem(401, "session_expired")
	}
	if errors.Is(err, _errInvalid) {
		return problem(401, "session_invalid")
	}
	if errors.Is(err, _errBusy) {
		return problem(409, "session_busy")
	}
	var denied *accessError
	if errors.As(err, &denied) {
		return problem(denied.status, denied.code)
	}
	return problem(503, "identity_provider_unavailable")
}
func (a *Runtime) accountCenter(r *http.Request, s *session) result {
	if _, _, err := a.currentRequest(r.Context(), s); err != nil {
		return classify(err)
	}
	target := a.config.Endpoint + "/account/organizations"
	return result{status: 302, redirect: target}
}

// Require 是直接 Logto 浏览器会话路由模式，不接受 Bearer 或旧 Account 身份。
func (a *Runtime) Require(scopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		called := false
		a.withSession(func(r *http.Request, s *session) result {
			if !a.csrfValid(r, s) {
				return problem(403, "csrf_rejected")
			}
			if s.Organization == "" {
				return problem(403, "organization_selection_required")
			}
			if _, _, err := a.currentRequest(r.Context(), s); err != nil {
				return classify(err)
			}
			if len(r.Header.Values("X-Organization-ID")) != 1 || len(r.Header.Values("X-Organization-Revision")) != 1 ||
				r.Header.Get("X-Organization-ID") != s.Organization || r.Header.Get("X-Organization-Revision") != s.Revision {
				return problem(409, "organization_identity_changed")
			}
			if a.config.APIResource == "" {
				if len(scopes) > 0 {
					return problem(403, "insufficient_scope")
				}
				deadline, err := sessionDeadline(s, a.store.nowTime())
				if err != nil {
					return classify(err)
				}
				p := Principal{Issuer: a.config.Endpoint + "/oidc", UserID: s.Subject, OrganizationID: s.Organization, OrganizationRevision: s.Revision, ExpiresAt: deadline.Unix()}
				return result{status: 200, principal: &p}
			}
			claims, err := a.organizationClaims(r.Context(), s, s.Organization)
			if err != nil {
				return classify(err)
			}
			for _, scope := range scopes {
				if scope == "" || !hasScope(claims, scope) {
					return problem(403, "insufficient_scope")
				}
			}
			deadline, err := sessionDeadline(s, a.store.nowTime())
			if err != nil {
				return classify(err)
			}
			expiresAt := claims.ExpiresAt.Unix()
			if deadline.Unix() < expiresAt {
				expiresAt = deadline.Unix()
			}
			p := Principal{Issuer: a.config.Endpoint + "/oidc", UserID: claims.Subject, OrganizationID: claims.OrganizationID, OrganizationRevision: s.Revision, DepartmentIDs: claims.DepartmentIDs, PrimaryDepartmentID: claims.PrimaryDepartmentID, Permissions: strings.Fields(claims.Scope), ExpiresAt: expiresAt}
			return result{status: 200, principal: &p}
		}, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { called = true; c.Request = r; c.Next() }))(c.Writer, c.Request)
		if !called {
			c.Abort()
		}
	}
}

// withSession 在发布业务主体前保存刷新凭据并释放有界租约；业务逻辑不持有认证租约。
func (a *Runtime) withSession(next sessionHandler, authorized ...http.Handler) http.HandlerFunc {
	if a.config.APIResource == "" {
		return a.withIdentitySession(next, authorized...)
	}
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
		var (
			originalRequest = r
			ctx, cancel     = context.WithTimeout(r.Context(), _authenticationTimeout)
		)
		defer cancel()
		r = r.WithContext(ctx)
		value, owner, err := a.store.acquire(r.Context(), cookie.Value)
		if err != nil {
			status, code := 503, "session_store_unavailable"
			if errors.Is(err, _errMissing) {
				status, code = 401, "session_expired"
			} else if errors.Is(err, _errInvalid) {
				status, code = 401, "session_invalid"
			} else if errors.Is(err, _errBusy) {
				status, code = 409, "session_busy"
			}
			fail(w, r, status, code)
			return
		}
		committed := false
		defer func() {
			if !committed {
				a.store.release(r.Context(), cookie.Value, owner)
			}
		}()
		var (
			previousOrganization, previousRevision = value.Organization, value.Revision
			outcome                                = next(r, value)
		)
		if value.Organization != "" && (previousOrganization != value.Organization || previousRevision != value.Revision) {
			outcome.rotate = true
		}
		if outcome.status == 401 {
			outcome.remove = true
		}
		nextID := cookie.Value
		if outcome.rotate {
			nextID, err = a.store.opaque()
			if err == nil {
				value.CSRF, err = a.store.opaque()
			}
			if err != nil {
				fail(w, r, 503, "session_entropy_unavailable")
				return
			}
		}
		save, cancelSave := context.WithTimeout(context.WithoutCancel(r.Context()), time.Second)
		defer cancelSave()
		if err = a.store.commit(save, cookie.Value, owner, nextID, value, outcome.remove); err != nil {
			fail(w, r, 503, "session_commit_failed")
			return
		}
		committed = true
		if outcome.remove {
			a.setCookie(w, a.config.CookieName, "", -1)
		} else if outcome.rotate {
			a.setCookie(w, a.config.CookieName, nextID, sessionCookieMaxAge(value, a.store.nowTime()))
			if v, ok := outcome.data.(map[string]any); ok {
				v["csrf_token"] = value.CSRF
			}
		}
		if outcome.principal != nil && len(authorized) == 1 {
			authorized[0].ServeHTTP(w, originalRequest.WithContext(a.authorizedContext(originalRequest.Context(), nextID, *outcome.principal)))
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

// jxlog:nonbusiness 只装配已验证主体和请求绑定能力，不执行外部副作用。
func (a *Runtime) authorizedContext(ctx context.Context, id string, principal Principal) context.Context {
	ctx = context.WithValue(ctx, principalKey{}, principal)
	ctx = context.WithValue(ctx, revalidationKey{}, func(ctx context.Context) error {
		return a.revalidate(ctx, id, principal, principal.Permissions)
	})
	return context.WithValue(ctx, resourceGrantRevokeKey{}, &resourceGrantRevokeCapability{
		runtime: a, id: id, principal: principal,
	})
}
