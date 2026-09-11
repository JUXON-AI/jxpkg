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

// Runtime is the immutable Account SSO integration for one business service.
// It owns the mTLS client and exposes only the already-validated dependencies
// that a business service needs to construct its router and authorize members.
type Runtime struct {
	origin    string
	resolver  *auth.InternalSessionResolverClient
	security  *middleware.BrowserSecurity
	cors      gin.HandlerFunc
	transport *http.Transport
}

// LoadEnv creates a Runtime from the established <PREFIX>_* deployment keys.
// Prefix must omit its trailing underscore; for example, JUXONONE reads
// JUXONONE_BROWSER_ALLOWED_HOSTS_JSON and JUXONONE_SESSION_RESOLVER_ENDPOINT.
func LoadEnv(getenv func(string) string, prefix string) (*Runtime, error) {
	if getenv == nil || !validPrefix(prefix) {
		return nil, auth.ErrAuthBackendUnavailable
	}

	hosts, err := decodeHosts(getenv(env(prefix, "BROWSER_ALLOWED_HOSTS_JSON")))
	if err != nil {
		return nil, auth.ErrAuthBackendUnavailable
	}
	transport, err := newResolverTransport(
		getenv(env(prefix, "SESSION_RESOLVER_TLS_CERT_FILE")),
		getenv(env(prefix, "SESSION_RESOLVER_TLS_KEY_FILE")),
		getenv(env(prefix, "SESSION_RESOLVER_CA_FILE")),
	)
	if err != nil {
		return nil, auth.ErrAuthBackendUnavailable
	}

	resolver, err := auth.NewInternalSessionResolverClient(auth.SessionResolverClientOptions{
		Endpoint:  getenv(env(prefix, "SESSION_RESOLVER_ENDPOINT")),
		Service:   getenv(env(prefix, "SESSION_RESOLVER_SERVICE")),
		Transport: transport,
		Timeout:   resolverResponseHeaderTimeout,
	})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}

	origin := getenv(env(prefix, "EXTERNAL_ORIGIN"))
	session := middleware.BrowserSessionOptions{
		Service:        getenv(env(prefix, "SESSION_RESOLVER_SERVICE")),
		CookieName:     getenv(env(prefix, "BROWSER_SESSION_COOKIE")),
		AllowedHosts:   hosts,
		ExternalOrigin: origin,
		Resolver:       resolver,
	}
	security, err := middleware.NewBrowserSecurity(session)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	cors, err := middleware.NewCORS(middleware.CORSOptions{ExternalOrigin: origin})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	return &Runtime{origin: origin, resolver: resolver, security: security, cors: cors, transport: transport}, nil
}

// Origin returns the normalized external origin after LoadEnv has validated it.
func (runtime *Runtime) Origin() string {
	if runtime == nil {
		return ""
	}
	return runtime.origin
}

// RouterOptions returns the complete browser-session security stack.
func (runtime *Runtime) RouterOptions() []server.RouterOption {
	if runtime == nil {
		return nil
	}
	return []server.RouterOption{
		server.WithCORS(runtime.cors),
		server.WithBrowserSecurity(runtime.security),
	}
}

// CompanyIdentityResolver returns Account's authoritative, mTLS-protected
// directory client. Business services must still make their own domain-level
// authorization decisions from these snapshots.
func (runtime *Runtime) CompanyIdentityResolver() auth.CompanyIdentityResolver {
	if runtime == nil {
		return nil
	}
	return runtime.resolver
}

// Close releases idle resolver connections during application shutdown.
func (runtime *Runtime) Close() {
	if runtime != nil && runtime.transport != nil {
		runtime.transport.CloseIdleConnections()
	}
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
		return nil, err
	}
	serverCAPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(serverCAPEM) {
		return nil, fmt.Errorf("invalid resolver CA")
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
