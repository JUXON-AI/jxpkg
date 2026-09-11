package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/JUXON-AI/jxpkg/apis/runtime/middleware"
	"github.com/JUXON-AI/jxpkg/config"
	"github.com/JUXON-AI/jxpkg/lifecycle"
	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

const (
	// PrefixAPIV1 v1 API 前缀。
	PrefixAPIV1 = "/v1/"
	// PrefixAPIDefault 默认 API 前缀。
	PrefixAPIDefault = "/v1/"

	// defaultGracefulShutdownTimeout bounds how long a process termination waits
	// for active API requests unless the application opts into a longer drain.
	defaultGracefulShutdownTimeout = 10 * time.Second
)

// MethodFunc Gin 路由注册方法类型（如 GET、POST）。
type MethodFunc func(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes

// Router 封装 Gin 路由引擎，支持多前缀注册和认证注入。
type Router struct {
	// eng 保存内部 Gin 路由引擎。
	eng *gin.Engine

	// l 保存服务当前使用的网络监听器。
	l net.Listener

	// serverMu protects httpServer while Run and Close coordinate startup and
	// graceful process termination.
	serverMu sync.RWMutex

	// httpServer owns active HTTP connections so Close can drain in-flight
	// requests instead of abruptly closing the listener during a rollout.
	httpServer *http.Server

	// gracefulShutdownTimeout must be shorter than the lifecycle and process
	// termination deadlines. Long-polling applications should override it with
	// WithGracefulShutdownTimeout.
	gracefulShutdownTimeout time.Duration

	// lc 保存服务生命周期控制器。
	lc *lifecycle.LifeCycle

	// Prefix 保存主 API 路由前缀。
	Prefix string

	// prefixes 保存去重后的全部 API 路由前缀。
	prefixes []string

	// pgr 保存主 API 前缀对应的路由组。
	pgr *gin.RouterGroup

	// routerMap 保存已注册的 Action。
	routerMap map[string]interface{}

	// routeGroups 保存每个 API 前缀对应的路由组。
	routeGroups map[string]*gin.RouterGroup

	// corsMiddleware 保存默认链首部调用的 CORS 中间件。
	corsMiddleware gin.HandlerFunc

	// browserSessionMiddleware 保存浏览器会话解析中间件。
	browserSessionMiddleware gin.HandlerFunc

	// browserCSRFMiddleware 保存浏览器会话 CSRF 中间件。
	browserCSRFMiddleware gin.HandlerFunc

	// browserBearerMiddleware selects the current Host's Cookie rejection boundary.
	browserBearerMiddleware gin.HandlerFunc

	// browserSessionErr 保存浏览器会话中间件的静态配置错误。
	browserSessionErr error

	// authInjector 保存业务认证主体注入器。
	*authInjector
}

// RouterOption Router 配置选项。
type RouterOption func(*Router)

// WithPrefixes 设置额外的路由前缀（去重后合并）。
func WithPrefixes(prefixes []string) RouterOption {
	return func(svr *Router) {
		if svr == nil {
			return
		}
		uniquePrefixes := make(map[string]struct{})
		if svr.Prefix != "" {
			uniquePrefixes[svr.Prefix] = struct{}{}
		}
		for _, p := range prefixes {
			if p != "" {
				uniquePrefixes[p] = struct{}{}
			}
		}
		svr.prefixes = make([]string, 0, len(uniquePrefixes))
		for p := range uniquePrefixes {
			svr.prefixes = append(svr.prefixes, p)
		}
	}
}

// WithMiddleware 添加全局中间件。
func WithMiddleware(middleware ...gin.HandlerFunc) RouterOption {
	return func(svr *Router) {
		svr.eng.Use(middleware...)
	}
}

// WithCORS 替换 Router 默认使用的 CORS 中间件。
func WithCORS(corsMiddleware gin.HandlerFunc) RouterOption {
	return func(svr *Router) {
		if svr == nil || corsMiddleware == nil {
			return
		}
		svr.corsMiddleware = corsMiddleware
	}
}

// NewBrowserSessionOption validates and installs the complete browser Session
// route boundary. Applications normally receive this option from sso.Runtime;
// they do not assemble the Session and CSRF middleware themselves.
func NewBrowserSessionOption(options middleware.BrowserSessionOptions) (RouterOption, error) {
	handlers, err := middleware.NewBrowserSessionHandlers(options)
	if err != nil {
		return nil, err
	}
	return func(svr *Router) {
		if svr == nil {
			return
		}
		svr.browserBearerMiddleware = handlers.Bearer
		svr.browserSessionMiddleware = handlers.Session
		svr.browserCSRFMiddleware = handlers.CSRF
		svr.browserSessionErr = nil
	}, nil
}

// WithGracefulShutdownTimeout sets the maximum time Close waits for active HTTP
// handlers. Non-positive values keep the ten-second default. Applications must
// configure their lifecycle and orchestrator termination deadlines to exceed
// this value.
func WithGracefulShutdownTimeout(timeout time.Duration) RouterOption {
	return func(svr *Router) {
		if svr == nil || timeout <= 0 {
			return
		}
		svr.gracefulShutdownTimeout = timeout
	}
}

// NewRouter 创建 Router 实例，默认启用 CORS、日志、Recovery、登录态等中间件。
func NewRouter(apiPrefix string, opts ...RouterOption) *Router {
	if apiPrefix == "" {
		apiPrefix = PrefixAPIDefault
	}
	svr := &Router{
		eng:                     gin.New(),
		lc:                      lifecycle.Std(),
		Prefix:                  apiPrefix,
		routerMap:               map[string]interface{}{},
		routeGroups:             map[string]*gin.RouterGroup{},
		authInjector:            &authInjector{},
		corsMiddleware:          middleware.CORS(),
		gracefulShutdownTimeout: defaultGracefulShutdownTimeout,
	}
	svr.router()
	for _, opt := range opts {
		opt(svr)
	}
	if len(svr.prefixes) == 0 {
		svr.prefixes = []string{svr.Prefix}
	}
	if config.Conf().MainConf.Env != "test" {
		gin.SetMode(gin.ReleaseMode)
	}
	for _, p := range svr.prefixes {
		svr.routeGroups[p] = svr.eng.Group(p)
	}
	svr.pgr = svr.eng.Group(apiPrefix)
	return svr
}

// Run 在指定 Listener 上启动 HTTP 服务，goroutine 中运行。服务会注册到当前
// lifecycle；进程退出时 Close 会先停止接收新连接，再等待进行中的请求完成。
func (svr *Router) Run(l net.Listener) error {
	if l == nil {
		return errors.New("server: nil listener")
	}

	svr.serverMu.Lock()
	if svr.httpServer != nil {
		svr.serverMu.Unlock()
		return errors.New("server: router is already running")
	}
	httpServer := &http.Server{Handler: svr.eng}
	svr.l = l
	svr.httpServer = httpServer
	svr.serverMu.Unlock()
	svr.lc.AddCloser(svr)

	go func() {
		if err := httpServer.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logs.Errorf("http server error: %v", err)
		}
		svr.lc.Exit()
	}()
	return nil
}

// Close gracefully stops the Router. New connections are rejected immediately,
// while in-flight handlers receive the configured drain interval before
// returning a shutdown error to the lifecycle's outer hard-stop policy.
func (svr *Router) Close() error {
	svr.serverMu.RLock()
	httpServer := svr.httpServer
	svr.serverMu.RUnlock()
	if httpServer == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), svr.gracefulShutdownTimeout)
	defer cancel()
	return httpServer.Shutdown(ctx)
}

// GinEngine 返回内部的 Gin 引擎。
func (svr *Router) GinEngine() *gin.Engine { return svr.eng }

func (svr *Router) router() {
	// 通过稳定的链首包装器延后读取选项，避免改变后续自定义中间件顺序。
	svr.eng.Use(func(ctx *gin.Context) {
		svr.corsMiddleware(ctx)
	})
	svr.eng.Use(middleware.CustomerHeader())
	svr.eng.Use(middleware.Logger(".Ping"))
	svr.eng.Use(middleware.Recovery())
	svr.eng.NoRoute(func(c *gin.Context) {
		c.String(http.StatusNotFound, "The incorrect API route.")
	})
}

// Any 注册所有 HTTP 方法匹配的路由。
func (svr *Router) Any(action string, hdrs ...interface{}) {
	svr.routerMap[action] = nil
	for _, pg := range svr.routeGroups {
		registerRoute(pg.Any, action, hdrs...)
	}
}

// Post 注册 POST 路由。
func (svr *Router) Post(action string, hdrs ...interface{}) {
	svr.routerMap[action] = nil
	for _, pg := range svr.routeGroups {
		registerRoute(pg.POST, action, hdrs...)
	}
}

// P 已废弃，请使用 Post。
func (svr *Router) P(action string, hdrs ...interface{}) {
	svr.Post(action, hdrs...)
}

// G 注册 GET 路由。
func (svr *Router) G(action string, hdrs ...interface{}) {
	svr.routerMap[action] = nil
	for _, pg := range svr.routeGroups {
		registerRoute(pg.GET, action, hdrs...)
	}
}

// PRequireBrowserSession registers a POST route behind the complete browser
// authentication boundary: resolve Session, publish the verified principal,
// require authentication, validate Origin/CSRF, then run business handlers.
func (svr *Router) PRequireBrowserSession(action string, handlers ...interface{}) {
	resolveSession, validateCSRF := svr.browserSessionHandlers()
	chain := []interface{}{
		resolveSession,
		svr.publishBrowserPrincipal,
		middleware.RequireAuthenticated,
		validateCSRF,
	}
	svr.Post(action, append(chain, handlers...)...)
}

// PRequireBearer 注册仅接受 Bearer Token 的 POST 路由。
func (svr *Router) PRequireBearer(action string, hdrs ...interface{}) {
	parser := svr.browserBearerMiddleware
	if parser == nil {
		parser = middleware.BearerLoginStatusMiddleware("")
	}
	newhdrs := append([]interface{}{parser, svr.Inject, middleware.RequireAuthenticated}, hdrs...)
	svr.Post(action, newhdrs...)
}

// PRequireLogin 注册保持旧版 Bearer 语义的 POST 路由。
// Deprecated: 请显式使用 PRequireBearer。
func (svr *Router) PRequireLogin(action string, hdrs ...interface{}) {
	svr.PRequireBearer(action, hdrs...)
}

func (svr *Router) browserSessionHandlers() (gin.HandlerFunc, gin.HandlerFunc) {
	if svr.browserSessionErr != nil {
		return unavailableLoginStatus(auth.AuthModeBrowserSession, svr.browserSessionErr), emptyMiddleware
	}
	if svr.browserSessionMiddleware == nil || svr.browserCSRFMiddleware == nil {
		err := fmt.Errorf("%w: browser session middleware is not configured", auth.ErrAuthBackendUnavailable)
		return unavailableLoginStatus(auth.AuthModeBrowserSession, err), emptyMiddleware
	}
	return svr.browserSessionMiddleware, svr.browserCSRFMiddleware
}

func unavailableLoginStatus(mode auth.AuthMode, err error) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Set(constants.CtxKeyLoginStatus, &auth.LoginStatus{
			Err:      err,
			State:    auth.StateFailed,
			AuthMode: mode,
		})
	}
}

func emptyMiddleware(*gin.Context) {}

func registerRoute(mf MethodFunc, action string, hdrs ...interface{}) {
	ginhdrs := make([]gin.HandlerFunc, 0, len(hdrs))
	for _, hdr := range hdrs {
		if hf, ok := hdr.(func(*gin.Context)); ok {
			ginhdrs = append(ginhdrs, hf)
		} else if hf, ok := hdr.(gin.HandlerFunc); ok {
			ginhdrs = append(ginhdrs, hf)
		} else if hf, ok := hdr.(func(http.ResponseWriter, *http.Request)); ok {
			ginhdrs = append(ginhdrs, transHttp(hf))
		} else if hf, ok := hdr.(http.HandlerFunc); ok {
			ginhdrs = append(ginhdrs, transHttp(hf))
		} else if hf, ok := hdr.(http.Handler); ok {
			ginhdrs = append(ginhdrs, transHttpHdr(hf))
		} else {
			ginhdrs = append(ginhdrs, transAPI(hdr))
		}
	}
	mf(action, ginhdrs...)
}

// ListAllRouters 列出所有路由
func (svr *Router) ListAllRouters() {
	rts := svr.eng.Routes()
	for _, rt := range rts {
		if strings.HasPrefix(rt.Path, PrefixAPIDefault) {
			cmd := strings.TrimPrefix(rt.Path, PrefixAPIDefault)
			logs.Infof("%v", cmd)
		}
	}
}

func (svr *Router) HandleDoc(model string) {
	for _, pg := range svr.routeGroups {
		pg.GET(model+".docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, ginSwagger.InstanceName(model)))
		pg.GET(model+".redocs", ReDocHandler(model, fmt.Sprintf("%s%s.docs/doc.json", pg.BasePath(), model)))
	}
}

// ReDocHandler 生成 ReDoc 文档页面的 ReDocHandler
// appName: 应用名称，如 "demoapp"
// swaggerURL: Swagger JSON 的 URL，如 "/v1/demoapp.docs/doc.json"
func ReDocHandler(appName, swaggerURL string) gin.HandlerFunc {
	return func(c *gin.Context) {
		html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>%s API Documentation</title>
	<meta charset="utf-8"/>
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<style>
		body {
			margin: 0;
			padding: 0;
		}
	</style>
</head>
<body>
	<redoc spec-url='%s'></redoc>
	<script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
</body>
</html>`, appName, swaggerURL)

		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, html)
	}
}
