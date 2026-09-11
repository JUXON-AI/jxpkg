package sso

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
)

// providerSessionFunc adapts an isolated authoritative session implementation.
type providerSessionFunc func(context.Context, auth.SessionResolveRequest) (*auth.SessionPrincipal, error)

func (resolve providerSessionFunc) Resolve(ctx context.Context, input auth.SessionResolveRequest) (*auth.SessionPrincipal, error) {
	return resolve(ctx, input)
}

// providerIdentityFunc adapts an isolated authoritative directory implementation.
type providerIdentityFunc func(context.Context, auth.CompanyIdentityResolveRequest) ([]auth.CompanyIdentity, error)

func (resolve providerIdentityFunc) ResolveCompanyIdentities(ctx context.Context, input auth.CompanyIdentityResolveRequest) ([]auth.CompanyIdentity, error) {
	return resolve(ctx, input)
}

func providerTestOptions() ProviderOptions {
	return ProviderOptions{
		Sessions: providerSessionFunc(func(_ context.Context, input auth.SessionResolveRequest) (*auth.SessionPrincipal, error) {
			return &auth.SessionPrincipal{Claims: auth.UserClaims{UserID: 1, UIN: 2, CompanyID: 3, MembershipEpoch: 4}, Host: input.Host, ClientID: "browser", SessionVersion: 1, AuthenticatedAt: 1, IdleExpiresAt: 2, AbsoluteExpiresAt: 3, CSRFTokenHash: make([]byte, 32)}, nil
		}),
		Identities: providerIdentityFunc(func(context.Context, auth.CompanyIdentityResolveRequest) ([]auth.CompanyIdentity, error) {
			return []auth.CompanyIdentity{{UIN: 2, MembershipEpoch: 4, Status: auth.CompanyIdentityStatusActive}}, nil
		}),
		ServiceHostAllowed: func(service, host string) bool { return service == "app" && host == "app.example.com" },
	}
}

func providerTestBody() string {
	return `{"host":"app.example.com","service":"app","session_id":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}`
}

func providerTestHandler(t *testing.T, options ProviderOptions) *Provider {
	t.Helper()
	callers, err := decodeProviderCallers(`[{"principal":"spiffe://test/app","service":"app","allowed_hosts":["app.example.com"]}]`, options.ServiceHostAllowed)
	if err != nil {
		t.Fatal(err)
	}
	return &Provider{sessions: options.Sessions, identities: options.Identities, callers: callers}
}

func providerTestRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://resolver.internal"+auth.InternalSessionResolvePath, strings.NewReader(body))
	principal, _ := url.Parse("spiffe://test/app")
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{principal}}}}}
	request.Header.Set("Content-Type", "application/json")
	return request
}

func TestProviderHandlerRejectsAmbiguousSessionRequests(t *testing.T) {
	provider := providerTestHandler(t, providerTestOptions())
	valid := providerTestBody()
	for _, test := range []struct {
		name, body string
		mutate     func(*http.Request)
		status     int
	}{
		{"valid", valid, nil, 200},
		{"duplicate", strings.Replace(valid, `"service":"app"`, `"service":"other","service":"app"`, 1), nil, 400},
		{"unknown", strings.Replace(valid, `"host":`, `"extra":1,"host":`, 1), nil, 400},
		{"missing", strings.Replace(valid, `"service":"app",`, "", 1), nil, 400},
		{"null", strings.Replace(valid, `"service":"app"`, `"service":null`, 1), nil, 400},
		{"trailing", valid + ` {}`, nil, 400},
		{"case_variant", strings.Replace(valid, `"service"`, `"Service"`, 1), nil, 400},
		{"wrong_service", strings.Replace(valid, `"service":"app"`, `"service":"other"`, 1), nil, 400},
		{"wrong_host", strings.Replace(valid, "app.example.com", "other.example.com", 1), nil, 401},
		{"invalid_sid", strings.Replace(valid, base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "sid", 1), nil, 400},
		{"oversize", valid + strings.Repeat(" ", 8193), nil, 400},
		{"no_tls", valid, func(r *http.Request) { r.TLS = nil }, 403},
		{"unverified_tls", valid, func(r *http.Request) { r.TLS.VerifiedChains = nil }, 403},
		{"multiple_uri", valid, func(r *http.Request) {
			r.TLS.VerifiedChains[0][0].URIs = append(r.TLS.VerifiedChains[0][0].URIs, r.TLS.VerifiedChains[0][0].URIs[0])
		}, 403},
		{"unknown_principal", valid, func(r *http.Request) { r.TLS.VerifiedChains[0][0].URIs[0].Path = "/other" }, 403},
		{"bearer", valid, func(r *http.Request) { r.Header.Set("Authorization", "Bearer test") }, 400},
		{"cookie", valid, func(r *http.Request) { r.Header.Set("Cookie", "session=test") }, 400},
		{"forwarded", valid, func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "app.example.com") }, 400},
		{"wrong_method", valid, func(r *http.Request) { r.Method = http.MethodGet }, 404},
		{"query", valid, func(r *http.Request) { r.URL.RawQuery = "extra=1" }, 404},
		{"wrong_type", valid, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := providerTestRequest(test.body)
			if test.mutate != nil {
				test.mutate(request)
			}
			writer := httptest.NewRecorder()
			provider.ServeHTTP(writer, request)
			if writer.Code != test.status {
				t.Fatalf("status=%d want=%d", writer.Code, test.status)
			}
			if writer.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
		})
	}
}

func TestProviderValidatesAuthorityResponses(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*auth.SessionPrincipal)
		err    error
		status int
	}{
		{"revoked", nil, auth.ErrInvalidCredential, 401},
		{"outage", nil, errors.New("database unavailable"), 503},
		{"wrong_host", func(p *auth.SessionPrincipal) { p.Host = "other.example.com" }, nil, 503},
		{"missing_epoch", func(p *auth.SessionPrincipal) { p.Claims.MembershipEpoch = 0 }, nil, 503},
		{"invalid_lifetime", func(p *auth.SessionPrincipal) { p.AbsoluteExpiresAt = 1 }, nil, 503},
		{"invalid_csrf", func(p *auth.SessionPrincipal) { p.CSRFTokenHash = nil }, nil, 503},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := providerTestOptions()
			original := options.Sessions
			options.Sessions = providerSessionFunc(func(ctx context.Context, request auth.SessionResolveRequest) (*auth.SessionPrincipal, error) {
				principal, _ := original.Resolve(ctx, request)
				if test.mutate != nil {
					test.mutate(principal)
				}
				return principal, test.err
			})
			writer := httptest.NewRecorder()
			providerTestHandler(t, options).ServeHTTP(writer, providerTestRequest(providerTestBody()))
			if writer.Code != test.status {
				t.Fatalf("status=%d want=%d", writer.Code, test.status)
			}
		})
	}
}

func TestProviderDirectoryProtocol(t *testing.T) {
	valid := `{"service":"app","company_id":3,"uins":[2]}`
	active := auth.CompanyIdentity{UIN: 2, MembershipEpoch: 4, Status: auth.CompanyIdentityStatusActive}
	for _, test := range []struct {
		name, body string
		rows       []auth.CompanyIdentity
		err        error
		status     int
	}{
		{"valid", valid, []auth.CompanyIdentity{active}, nil, 200},
		{"empty", valid, nil, nil, 200},
		{"duplicate_field", `{"service":"app","service":"app","company_id":3,"uins":[2]}`, nil, nil, 400},
		{"unknown", `{"service":"app","company_id":3,"uins":[2],"extra":1}`, nil, nil, 400},
		{"missing", `{"service":"app","uins":[2]}`, nil, nil, 400},
		{"trailing", valid + ` {}`, nil, nil, 400},
		{"duplicate_uin", `{"service":"app","company_id":3,"uins":[2,2]}`, nil, nil, 400},
		{"unrequested_row", valid, []auth.CompanyIdentity{{UIN: 9, MembershipEpoch: 4, Status: auth.CompanyIdentityStatusActive}}, nil, 503},
		{"duplicate_row", valid, []auth.CompanyIdentity{active, active}, nil, 503},
		{"invalid_row", valid, []auth.CompanyIdentity{{UIN: 2}}, nil, 503},
		{"inactive_owner", valid, []auth.CompanyIdentity{{UIN: 2, MembershipEpoch: 4, Status: auth.CompanyIdentityStatusDisabled, IsCompanyOwner: true}}, nil, 503},
		{"missing_company", valid, nil, auth.ErrCompanyIdentityNotFound, 404},
		{"outage", valid, nil, auth.ErrAuthBackendUnavailable, 503},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := providerTestOptions()
			options.Identities = providerIdentityFunc(func(context.Context, auth.CompanyIdentityResolveRequest) ([]auth.CompanyIdentity, error) {
				return test.rows, test.err
			})
			request := providerTestRequest(test.body)
			request.URL.Path = auth.InternalCompanyIdentityResolvePath
			writer := httptest.NewRecorder()
			providerTestHandler(t, options).ServeHTTP(writer, request)
			if writer.Code != test.status {
				t.Fatalf("status=%d want=%d", writer.Code, test.status)
			}
			if test.name == "empty" && !strings.Contains(writer.Body.String(), `"identities":[]`) {
				t.Fatal("empty directory must encode an array")
			}
		})
	}
}

// providerTestTrust creates a server and two clients signed by one isolated CA.
func providerTestTrust(t *testing.T) (map[string]string, *tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	directory := t.TempDir()
	caFile := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(caFile, rootPEM, 0600); err != nil {
		t.Fatal(err)
	}
	issue := func(name string, serial int64, server bool) (tls.Certificate, string, string) {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature}
		if server {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			principal, _ := url.Parse("spiffe://test/" + name)
			template.URIs = []*url.URL{principal}
		}
		encoded, err := x509.CreateCertificate(rand.Reader, template, ca, &private.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		privateDER, err := x509.MarshalECPrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER})
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		certFile, keyFile := filepath.Join(directory, name+".crt"), filepath.Join(directory, name+".key")
		if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
			t.Fatal(err)
		}
		return cert, certFile, keyFile
	}
	_, certFile, keyFile := issue("server", 2, true)
	client, _, _ := issue("app", 3, false)
	unknown, _, _ := issue("unknown", 4, false)
	values := map[string]string{"ACCOUNT_SESSION_RESOLVER_ADDR": "127.0.0.1:0", "ACCOUNT_SESSION_RESOLVER_CALLERS_JSON": `[{"principal":"spiffe://test/app","service":"app","allowed_hosts":["app.example.com"]}]`, "ACCOUNT_SESSION_RESOLVER_TLS_CERT_FILE": certFile, "ACCOUNT_SESSION_RESOLVER_TLS_KEY_FILE": keyFile, "ACCOUNT_SESSION_RESOLVER_CLIENT_CA_FILE": caFile}
	return values, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{client}}, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{unknown}}
}

func TestProviderRealTLSAndLifecycle(t *testing.T) {
	values, trusted, unknown := providerTestTrust(t)
	var resolved atomic.Int32
	options := providerTestOptions()
	original := options.Sessions
	options.Sessions = providerSessionFunc(func(ctx context.Context, input auth.SessionResolveRequest) (*auth.SessionPrincipal, error) {
		resolved.Add(1)
		return original.Resolve(ctx, input)
	})
	provider, err := LoadProviderEnv(func(key string) string { return values[key] }, "ACCOUNT", options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	results := make(chan error, 2)
	go func() { results <- provider.Serve() }()
	go func() { results <- provider.Serve() }()
	for _, test := range []struct {
		name   string
		config *tls.Config
		status int
	}{
		{"verified", trusted, 200}, {"unknown_spiffe", unknown, 403},
		{"missing_client", &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: trusted.RootCAs}, 0},
		{"wrong_ca", &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: x509.NewCertPool(), Certificates: trusted.Certificates}, 0},
		{"tls12", &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, RootCAs: trusted.RootCAs, Certificates: trusted.Certificates}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &http.Transport{TLSClientConfig: test.config}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: time.Second}
			response, err := client.Post("https://"+provider.Addr().String()+auth.InternalSessionResolvePath, "application/json", strings.NewReader(providerTestBody()))
			if test.status == 0 {
				if err == nil {
					response.Body.Close()
					t.Fatal("TLS trust unexpectedly accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != test.status {
				t.Fatalf("status=%d want=%d", response.StatusCode, test.status)
			}
			if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || len(response.TLS.VerifiedChains) == 0 {
				t.Fatal("response lacks verified TLS1.3")
			}
		})
	}
	if resolved.Load() != 1 {
		t.Fatal("untrusted requests reached authority")
	}
	var closers sync.WaitGroup
	for index := 0; index < 3; index++ {
		closers.Add(1)
		go func() {
			defer closers.Done()
			if err := provider.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	closers.Wait()
	for index := 0; index < 2; index++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("Serve did not stop")
		}
	}
}

func TestProviderCloseBeforeServe(t *testing.T) {
	values, _, _ := providerTestTrust(t)
	provider, err := LoadProviderEnv(func(key string) string { return values[key] }, "ACCOUNT", providerTestOptions())
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if err := provider.Serve(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", provider.Addr().String())
	if err != nil {
		t.Fatal("Close leaked listener")
	}
	listener.Close()
}

func TestProviderCloseDrainsAndBoundsActiveRequests(t *testing.T) {
	for _, force := range []bool{false, true} {
		name := "graceful"
		if force {
			name = "deadline_forces_connection_close"
		}
		t.Run(name, func(t *testing.T) {
			values, trusted, _ := providerTestTrust(t)
			options := providerTestOptions()
			original := options.Sessions
			entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			options.Sessions = providerSessionFunc(func(ctx context.Context, input auth.SessionResolveRequest) (*auth.SessionPrincipal, error) {
				defer close(finished)
				close(entered)
				select {
				case <-release:
					return original.Resolve(ctx, input)
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			})
			provider, err := LoadProviderEnv(func(key string) string { return values[key] }, "ACCOUNT", options)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = provider.Close() })
			served := make(chan error, 1)
			go func() { served <- provider.Serve() }()
			transport := &http.Transport{TLSClientConfig: trusted}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			requested := make(chan error, 1)
			go func() {
				response, err := client.Post("https://"+provider.Addr().String()+auth.InternalSessionResolvePath, "application/json", strings.NewReader(providerTestBody()))
				if response != nil {
					_, _ = io.Copy(io.Discard, response.Body)
					response.Body.Close()
					if response.StatusCode != http.StatusOK {
						err = errors.New("request was not completed")
					}
				}
				requested <- err
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("request did not reach authority")
			}
			closed := make(chan error, 1)
			go func() { closed <- provider.Close() }()
			if !force {
				select {
				case <-closed:
					t.Fatal("Close returned before active request drained")
				case <-time.After(20 * time.Millisecond):
				}
				close(release)
			}
			select {
			case err := <-closed:
				if force && !errors.Is(err, context.DeadlineExceeded) || !force && err != nil {
					t.Fatalf("Close error=%v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Close exceeded drain bound")
			}
			select {
			case err := <-requested:
				if !force && err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("request connection was not closed")
			}
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("authority context was not cancelled")
			}
			if err := <-served; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProviderInvalidConfiguration(t *testing.T) {
	values, _, _ := providerTestTrust(t)
	for key := range values {
		t.Run(key, func(t *testing.T) {
			_, err := LoadProviderEnv(func(name string) string {
				if name == key {
					return ""
				}
				return values[name]
			}, "ACCOUNT", providerTestOptions())
			if !errors.Is(err, auth.ErrAuthBackendUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	for _, raw := range []string{`[]`, `null`, `[{}]`, `[{"principal":"spiffe://test/app","service":"app","service":"app","allowed_hosts":["app.example.com"]}]`, values["ACCOUNT_SESSION_RESOLVER_CALLERS_JSON"] + ` []`, strings.Replace(values["ACCOUNT_SESSION_RESOLVER_CALLERS_JSON"], "app.example.com", "other.example.com", 1)} {
		if _, err := decodeProviderCallers(raw, providerTestOptions().ServiceHostAllowed); err == nil {
			t.Fatal("invalid caller configuration accepted")
		}
	}
}

// Keep the shared wire DTO directly decodable by standard library users.
func TestProviderResponseUsesSharedWireDTO(t *testing.T) {
	writer := httptest.NewRecorder()
	providerTestHandler(t, providerTestOptions()).ServeHTTP(writer, providerTestRequest(providerTestBody()))
	var response auth.SessionResolveResponse
	if err := json.NewDecoder(bytes.NewReader(writer.Body.Bytes())).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.UserID != 1 || response.MembershipEpoch != 4 {
		t.Fatal("wire identity changed")
	}
	_, _ = io.Copy(io.Discard, writer.Result().Body)
}
