// Package sso provides the fail-closed, application-side runtime for JX Account SSO.
package sso

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/JUXON-AI/jxpkg/apis/runtime/middleware"
	"github.com/JUXON-AI/jxpkg/apis/runtime/server"
	"github.com/gin-gonic/gin"
)

const (
	resolverDialTimeout           = 500 * time.Millisecond
	resolverTLSHandshakeTimeout   = 500 * time.Millisecond
	resolverResponseHeaderTimeout = 2 * time.Second
)

// Runtime is the immutable SSO integration for one business service. Account
// mode owns an mTLS client; local mode supplies the same application contracts
// from one loopback-only development identity.
type Runtime struct {
	httpAddress  string
	origin       string
	resolver     authorizationResolver
	routerOption server.RouterOption
	transport    *http.Transport
}

type authorizationResolver interface {
	auth.CompanyIdentityResolver
	auth.AuthorizationContextResolver
	auth.AuthorizationSubjectsResolver
}

type runtimeOptions struct {
	httpAddress string
	devIdentity *DevIdentity
}

// RuntimeOption customizes Runtime construction without changing the
// environment contract used by existing services.
type RuntimeOption func(*runtimeOptions) error

// WithHTTPAddress supplies the application's configured HTTP listener. Local
// development narrows wildcard listeners to IPv4 loopback; an explicit
// <PREFIX>_HTTP_ADDR still takes precedence.
func WithHTTPAddress(address string) RuntimeOption {
	return func(options *runtimeOptions) error {
		if address == "" || address != strings.TrimSpace(address) {
			return fmt.Errorf("%w: invalid application HTTP address", auth.ErrAuthBackendUnavailable)
		}
		options.httpAddress = address
		return nil
	}
}

// WithDevIdentity selects the loopback-only local Runtime when identity is
// non-zero. The zero value leaves mode selection to <PREFIX>_SSO_MODE.
func WithDevIdentity(identity DevIdentity) RuntimeOption {
	return func(options *runtimeOptions) error {
		if identity.isZero() {
			return nil
		}
		if !identity.valid() {
			return fmt.Errorf("%w: invalid development identity", auth.ErrAuthBackendUnavailable)
		}
		identityCopy := identity
		options.devIdentity = &identityCopy
		return nil
	}
}

// LoadEnv creates a Runtime from <PREFIX>_* keys and optional process-local
// settings. WithDevIdentity selects the loopback-only development identity;
// otherwise SSO_MODE=local reads the configured file, while omitted or account
// selects Account mTLS. Prefix must omit its trailing underscore; for example,
// JUXONONE.
func LoadEnv(getenv func(string) string, prefix string, optionList ...RuntimeOption) (*Runtime, error) {
	if getenv == nil || !validPrefix(prefix) {
		return nil, auth.ErrAuthBackendUnavailable
	}
	options := runtimeOptions{}
	for _, option := range optionList {
		if option == nil {
			return nil, auth.ErrAuthBackendUnavailable
		}
		if err := option(&options); err != nil {
			return nil, err
		}
	}
	mode := getenv(env(prefix, "SSO_MODE"))
	if options.devIdentity != nil {
		return loadLocalEnv(getenv, prefix, options)
	}
	if mode == "local" {
		return loadLocalEnv(getenv, prefix, options)
	}
	if mode != "" && mode != "account" {
		return nil, fmt.Errorf("%w: invalid %s", auth.ErrAuthBackendUnavailable, env(prefix, "SSO_MODE"))
	}
	httpAddress, err := accountHTTPAddress(getenv(env(prefix, "HTTP_ADDR")), options.httpAddress)
	if err != nil {
		return nil, err
	}
	// Validate required deployment keys before opening certificate files. Error
	// messages identify only the key or stage, never configured values.
	for _, key := range []string{
		"BROWSER_ALLOWED_HOSTS_JSON",
		"BROWSER_SESSION_COOKIE",
		"EXTERNAL_ORIGIN",
		"SESSION_RESOLVER_ENDPOINT",
		"SESSION_RESOLVER_SERVICE",
		"SESSION_RESOLVER_TLS_CERT_FILE",
		"SESSION_RESOLVER_TLS_KEY_FILE",
		"SESSION_RESOLVER_CA_FILE",
	} {
		if strings.TrimSpace(getenv(env(prefix, key))) == "" {
			return nil, fmt.Errorf("%w: required %s", auth.ErrAuthBackendUnavailable, env(prefix, key))
		}
	}

	hosts, err := decodeHosts(getenv(env(prefix, "BROWSER_ALLOWED_HOSTS_JSON")))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid %s", auth.ErrAuthBackendUnavailable, env(prefix, "BROWSER_ALLOWED_HOSTS_JSON"))
	}
	transport, err := newResolverTransport(
		getenv(env(prefix, "SESSION_RESOLVER_TLS_CERT_FILE")),
		getenv(env(prefix, "SESSION_RESOLVER_TLS_KEY_FILE")),
		getenv(env(prefix, "SESSION_RESOLVER_CA_FILE")),
	)
	if err != nil {
		return nil, err
	}

	resolver, err := auth.NewInternalSessionResolverClient(auth.SessionResolverClientOptions{
		Endpoint:  getenv(env(prefix, "SESSION_RESOLVER_ENDPOINT")),
		Service:   getenv(env(prefix, "SESSION_RESOLVER_SERVICE")),
		Transport: transport,
		Timeout:   resolverResponseHeaderTimeout,
	})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("%w: invalid resolver endpoint or service", auth.ErrAuthBackendUnavailable)
	}

	origin := getenv(env(prefix, "EXTERNAL_ORIGIN"))
	primaryCORS, err := middleware.NewCORS(middleware.CORSOptions{ExternalOrigin: origin})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("%w: invalid CORS external origin", auth.ErrAuthBackendUnavailable)
	}
	parsedOrigin, err := url.Parse(origin)
	if err != nil || parsedOrigin == nil {
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("%w: invalid external origin", auth.ErrAuthBackendUnavailable)
	}
	if _, ok := hosts[parsedOrigin.Host]; !ok {
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("%w: external origin host is not allowed", auth.ErrAuthBackendUnavailable)
	}
	bindings := make([]middleware.BrowserSessionBinding, 0, len(hosts))
	for host := range hosts {
		bindings = append(bindings, middleware.BrowserSessionBinding{
			Host:           host,
			Service:        getenv(env(prefix, "SESSION_RESOLVER_SERVICE")),
			CookieName:     getenv(env(prefix, "BROWSER_SESSION_COOKIE")),
			ExternalOrigin: parsedOrigin.Scheme + "://" + host,
		})
	}
	session := middleware.BrowserSessionOptions{
		Bindings: bindings,
		Resolver: resolver,
	}
	browserSession, err := server.NewBrowserSessionOption(session)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("%w: invalid browser cookie, hosts or external origin", auth.ErrAuthBackendUnavailable)
	}
	corsByHost := make(map[string]gin.HandlerFunc, len(bindings))
	corsByHost[parsedOrigin.Host] = primaryCORS
	for _, binding := range bindings {
		if binding.Host == parsedOrigin.Host {
			continue
		}
		cors, err := middleware.NewCORS(middleware.CORSOptions{ExternalOrigin: binding.ExternalOrigin})
		if err != nil {
			transport.CloseIdleConnections()
			return nil, fmt.Errorf("%w: invalid binding CORS origin", auth.ErrAuthBackendUnavailable)
		}
		corsByHost[binding.Host] = cors
	}
	cors := func(ctx *gin.Context) {
		// Internal service requests have no browser Origin. Preserve the original
		// CORS behavior and let the route's own authentication boundary decide.
		if len(ctx.Request.Header.Values("Origin")) == 0 {
			primaryCORS(ctx)
			return
		}
		handler, ok := corsByHost[ctx.Request.Host]
		if !ok {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		handler(ctx)
	}
	routerOption := func(router *server.Router) {
		server.WithCORS(cors)(router)
		browserSession(router)
	}
	return &Runtime{
		httpAddress:  httpAddress,
		origin:       origin,
		resolver:     resolver,
		routerOption: routerOption,
		transport:    transport,
	}, nil
}

// HTTPAddress returns the validated listener selected during Runtime
// construction. It is non-empty when WithHTTPAddress was supplied or
// <PREFIX>_HTTP_ADDR was configured.
func (runtime *Runtime) HTTPAddress() string {
	return runtime.httpAddress
}

// Origin returns the normalized external origin after LoadEnv has validated it.
func (runtime *Runtime) Origin() string {
	return runtime.origin
}

// RouterOption returns the complete, already validated browser authentication
// boundary. Applications install it once and never assemble SSO middleware.
func (runtime *Runtime) RouterOption() server.RouterOption {
	return runtime.routerOption
}

// CompanyIdentityResolver returns the identity directory selected by LoadEnv.
// Business services still make their own domain authorization decisions.
func (runtime *Runtime) CompanyIdentityResolver() auth.CompanyIdentityResolver {
	return runtime.resolver
}

// AuthorizationContextResolver 返回 Account 的权威授权上下文解析客户端。
func (runtime *Runtime) AuthorizationContextResolver() auth.AuthorizationContextResolver {
	return runtime.resolver
}

// AuthorizationSubjectsResolver 返回 Account 的权威同组织授权主体目录客户端。
func (runtime *Runtime) AuthorizationSubjectsResolver() auth.AuthorizationSubjectsResolver {
	return runtime.resolver
}

// Close releases idle resolver connections during application shutdown.
func (runtime *Runtime) Close() error {
	if runtime.transport != nil {
		runtime.transport.CloseIdleConnections()
	}
	return nil
}

func env(prefix, key string) string { return prefix + "_" + key }

func validPrefix(prefix string) bool {
	if prefix == "" || strings.TrimSpace(prefix) != prefix || strings.HasSuffix(prefix, "_") {
		return false
	}
	for _, character := range prefix {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func decodeHosts(raw string) (map[string]struct{}, error) {
	var values []string
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&values); err != nil || len(values) == 0 {
		return nil, fmt.Errorf("invalid allowed hosts")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid allowed hosts")
	}
	hosts := make(map[string]struct{}, len(values))
	for _, host := range values {
		if _, duplicate := hosts[host]; duplicate {
			return nil, fmt.Errorf("duplicate allowed host")
		}
		hosts[host] = struct{}{}
	}
	return hosts, nil
}

func newResolverTransport(certFile, keyFile, caFile string) (*http.Transport, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("%w: resolver client certificate/key could not be loaded", auth.ErrAuthBackendUnavailable)
	}
	serverCAPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("%w: resolver CA file could not be read", auth.ErrAuthBackendUnavailable)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(serverCAPEM) {
		return nil, fmt.Errorf("%w: invalid resolver CA bundle", auth.ErrAuthBackendUnavailable)
	}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: resolverDialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   resolverTLSHandshakeTimeout,
		ResponseHeaderTimeout: resolverResponseHeaderTimeout,
		ExpectContinueTimeout: 100 * time.Millisecond,
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      rootCAs,
			Certificates: []tls.Certificate{certificate},
		},
	}, nil
}
