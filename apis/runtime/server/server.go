package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

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
)

// MethodFunc Gin 路由注册方法类型（如 GET、POST）。
type MethodFunc func(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes

// Router 封装 Gin 路由引擎，支持多前缀注册和认证注入。
type Router struct {
	eng      *gin.Engine
	l        net.Listener
	http     *http.Server
	lc       *lifecycle.LifeCycle
	Prefix   string
	prefixes []string
	pgr      *gin.RouterGroup

	routerMap   map[string]interface{}
	routeGroups map[string]*gin.RouterGroup

	*authInjectors
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

// NewRouter 创建 Router 实例，默认启用 CORS、日志、Recovery、登录态等中间件。
func NewRouter(apiPrefix string, opts ...RouterOption) *Router {
	if apiPrefix == "" {
		apiPrefix = PrefixAPIDefault
	}
	svr := &Router{
		eng:         gin.New(),
		lc:          lifecycle.Std(),
		Prefix:      apiPrefix,
		routerMap:   map[string]interface{}{},
		routeGroups: map[string]*gin.RouterGroup{},
		authInjectors: &authInjectors{
			injectors: map[string]auth.InjectorFunc{},
			defaultInjector: func(ctx *gin.Context, ls *auth.LoginStatus) error {
				return nil
			},
		},
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

// Run 在指定 Listener 上启动 HTTP 服务，goroutine 中运行。
func (svr *Router) Run(l net.Listener) error {
	if l == nil {
		return fmt.Errorf("listener is nil")
	}
	svr.l = l
	svr.http = &http.Server{
		Handler:           svr.eng,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	svr.lc.AddCloser(svr)
	go func() {
		if err := svr.http.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logs.Errorf("http server error: %v", err)
			svr.lc.Exit()
		}
	}()
	return nil
}

// Close gracefully stops the HTTP server.
func (svr *Router) Close() error {
	if svr.http == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return svr.http.Shutdown(ctx)
}

// GinEngine 返回内部的 Gin 引擎。
func (svr *Router) GinEngine() *gin.Engine { return svr.eng }

func (svr *Router) router() {
	svr.eng.Use(middleware.CORS())
	svr.eng.Use(middleware.CustomerHeader())
	svr.eng.Use(middleware.Logger(".Ping"))
	svr.eng.Use(middleware.Recovery())
	svr.eng.Use(middleware.LoginStatus())
	svr.eng.Use(middleware.AcceptLanguage())
	svr.eng.Use(svr.Inject)
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

// PRequireLogin 注册需要登录的 POST 路由。
func (svr *Router) PRequireLogin(action string, hdrs ...interface{}) {
	newhdrs := append([]interface{}{middleware.AuthMiddleWare}, hdrs...)
	svr.Post(action, newhdrs...)
}

// PRequireEmployee 注册需要员工权限的 POST 路由。
func (svr *Router) PRequireEmployee(action string, hdrs ...interface{}) {
	newhdrs := append([]interface{}{middleware.AuthMiddleWareEmployee}, hdrs...)
	svr.Post(action, newhdrs...)
}

// GRequireLogin 注册需要登录的 GET 路由。
func (svr *Router) GRequireLogin(action string, hdrs ...interface{}) {
	newhdrs := append([]interface{}{middleware.AuthMiddleWare}, hdrs...)
	svr.G(action, newhdrs...)
}

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
