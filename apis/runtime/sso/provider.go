package sso

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
)

const (
	// providerShutdownTimeout bounds graceful draining before force-closing requests.
	providerShutdownTimeout = 3 * time.Second
)

// ProviderAuthority is the single Account-owned authority consumed by the mTLS
// Provider. Provider does not own or close the implementation.
type ProviderAuthority interface {
	auth.SessionResolver
	auth.CompanyIdentityResolver
	ServiceHostAllowed(service, host string) bool
}

// providerCaller is a frozen workload registration read from deployment configuration.
type providerCaller struct {
	// Principal is the only accepted URI SAN in a verified client certificate.
	Principal string `json:"principal"`
	// Service binds the workload to its registered service name.
	Service string `json:"service"`
	// AllowedHosts is the startup-validated set of business session hosts.
	AllowedHosts []string `json:"allowed_hosts"`
}

// Provider owns the internal TLS listener and exposes the two fixed resolver paths.
// Its authority adapters remain application-owned and are never closed by Provider.
type Provider struct {
	authority ProviderAuthority
	callers   map[string]providerCaller
	listener  net.Listener
	server    *http.Server
	serveOnce sync.Once
	serveErr  error
	closeOnce sync.Once
	closeErr  error
}

// LoadProviderEnv validates <PREFIX>_SESSION_RESOLVER_* and binds the internal listener.
// ACCOUNT preserves the existing Account environment contract. Call Serve after startup
// is complete, and register Close with the application's shutdown lifecycle.
func LoadProviderEnv(getenv func(string) string, prefix string, authority ProviderAuthority) (*Provider, error) {
	if getenv == nil || !validPrefix(prefix) || authority == nil {
		return nil, auth.ErrAuthBackendUnavailable
	}
	for _, suffix := range []string{"ADDR", "CALLERS_JSON", "TLS_CERT_FILE", "TLS_KEY_FILE", "CLIENT_CA_FILE"} {
		key := env(prefix, "SESSION_RESOLVER_"+suffix)
		if strings.TrimSpace(getenv(key)) == "" {
			return nil, fmt.Errorf("%w: required %s", auth.ErrAuthBackendUnavailable, key)
		}
	}
	callers, err := decodeProviderCallers(getenv(env(prefix, "SESSION_RESOLVER_CALLERS_JSON")), authority.ServiceHostAllowed)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid resolver callers", auth.ErrAuthBackendUnavailable)
	}
	certificate, err := tls.LoadX509KeyPair(getenv(env(prefix, "SESSION_RESOLVER_TLS_CERT_FILE")), getenv(env(prefix, "SESSION_RESOLVER_TLS_KEY_FILE")))
	if err != nil {
		return nil, fmt.Errorf("%w: resolver server certificate/key could not be loaded", auth.ErrAuthBackendUnavailable)
	}
	caPEM, err := os.ReadFile(getenv(env(prefix, "SESSION_RESOLVER_CLIENT_CA_FILE")))
	if err != nil {
		return nil, fmt.Errorf("%w: resolver client CA could not be read", auth.ErrAuthBackendUnavailable)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w: invalid resolver client CA", auth.ErrAuthBackendUnavailable)
	}
	address := getenv(env(prefix, "SESSION_RESOLVER_ADDR"))
	if strings.TrimSpace(address) != address {
		return nil, fmt.Errorf("%w: invalid resolver address", auth.ErrAuthBackendUnavailable)
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("%w: resolver listener could not bind", auth.ErrAuthBackendUnavailable)
	}
	provider := &Provider{authority: authority, callers: callers}
	provider.listener = tls.NewListener(listener, &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs, NextProtos: []string{"http/1.1"},
	})
	provider.server = &http.Server{Handler: http.HandlerFunc(provider.serveHTTP), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	return provider, nil
}

// Serve handles internal requests until Close; repeated calls share the same result.
func (provider *Provider) Serve() error {
	provider.serveOnce.Do(func() {
		provider.serveErr = provider.server.Serve(provider.listener)
		if errors.Is(provider.serveErr, http.ErrServerClosed) {
			provider.serveErr = nil
		}
	})
	return provider.serveErr
}

// Close drains in-flight requests for three seconds, then closes remaining connections.
// It also closes a listener when Serve has not yet started and is safe to call repeatedly.
func (provider *Provider) Close() error {
	provider.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), providerShutdownTimeout)
		defer cancel()
		provider.closeErr = provider.server.Shutdown(ctx)
		if provider.closeErr != nil {
			_ = provider.server.Close()
		}
		if err := provider.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) && provider.closeErr == nil {
			provider.closeErr = err
		}
	})
	return provider.closeErr
}

func decodeProviderCallers(raw string, allowed func(string, string) bool) (map[string]providerCaller, error) {
	if len(raw) > 1024*1024 {
		return nil, auth.ErrInvalidCredential
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('[') {
		return nil, auth.ErrInvalidCredential
	}
	callers := make(map[string]providerCaller)
	for decoder.More() {
		var caller providerCaller
		opening, err := decoder.Token()
		if err != nil || opening != json.Delim('{') {
			return nil, auth.ErrInvalidCredential
		}
		seen := make(map[string]bool, 3)
		for decoder.More() {
			token, err := decoder.Token()
			name, ok := token.(string)
			if err != nil || !ok || seen[name] {
				return nil, auth.ErrInvalidCredential
			}
			seen[name] = true
			switch name {
			case "principal":
				err = decoder.Decode(&caller.Principal)
			case "service":
				err = decoder.Decode(&caller.Service)
			case "allowed_hosts":
				err = decoder.Decode(&caller.AllowedHosts)
			default:
				return nil, auth.ErrInvalidCredential
			}
			if err != nil {
				return nil, auth.ErrInvalidCredential
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') || len(seen) != 3 || !validProviderPrincipal(caller.Principal) || !validProviderIdentifier(caller.Service) || len(caller.AllowedHosts) == 0 {
			return nil, auth.ErrInvalidCredential
		}
		if _, duplicate := callers[caller.Principal]; duplicate {
			return nil, auth.ErrInvalidCredential
		}
		hosts := make(map[string]bool, len(caller.AllowedHosts))
		for _, host := range caller.AllowedHosts {
			if hosts[host] || !canonicalProviderHost(host) || !allowed(caller.Service, host) {
				return nil, auth.ErrInvalidCredential
			}
			hosts[host] = true
		}
		callers[caller.Principal] = caller
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim(']') || len(callers) == 0 {
		return nil, auth.ErrInvalidCredential
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, auth.ErrInvalidCredential
	}
	return callers, nil
}

func canonicalProviderHost(host string) bool {
	parsed, err := url.Parse("https://" + host)
	return err == nil && host != "" && host == strings.ToLower(host) && parsed.Host == host && parsed.User == nil && parsed.Port() == "" && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && !strings.ContainsAny(host, " \t\r\n")
}

func validProviderIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func validProviderPrincipal(principal string) bool {
	parsed, err := url.Parse(principal)
	return err == nil && parsed.Scheme == "spiffe" && parsed.Host != "" && parsed.Host == strings.ToLower(parsed.Host) && parsed.Port() == "" && parsed.User == nil && strings.HasPrefix(parsed.Path, "/") && parsed.Path != "/" && parsed.RawPath == "" && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == principal
}

var _ io.Closer = (*Provider)(nil)
