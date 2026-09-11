package sso

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/JUXON-AI/jxpkg/apis/runtime/server"
	"github.com/gin-gonic/gin"
)

func TestValidPrefix(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{value: "JUXONONE", want: true},
		{value: "MY_APP_2", want: true},
		{value: "", want: false},
		{value: "JUXONONE_", want: false},
		{value: "juxonone", want: false},
		{value: "JUXONONE-API", want: false},
	} {
		if got := validPrefix(test.value); got != test.want {
			t.Fatalf("validPrefix(%q) = %v, want %v", test.value, got, test.want)
		}
	}
}

func TestDecodeHostsRejectsAmbiguousInput(t *testing.T) {
	for _, raw := range []string{"", "[]", "[\"one.example.com\",\"one.example.com\"]", "[\"one.example.com\"] {}"} {
		if _, err := decodeHosts(raw); err == nil {
			t.Fatalf("decodeHosts(%q) unexpectedly succeeded", raw)
		}
	}
	hosts, err := decodeHosts("[\"one.example.com\",\"api.example.com\"]")
	if err != nil || len(hosts) != 2 {
		t.Fatalf("decodeHosts(valid) = %#v, %v", hosts, err)
	}
}

func TestLoadEnvFailsClosedBeforeReadingFiles(t *testing.T) {
	if runtime, err := LoadEnv(nil, "JUXONONE"); err == nil || runtime != nil {
		t.Fatalf("LoadEnv(nil) = %#v, %v", runtime, err)
	}
	if runtime, err := LoadEnv(func(string) string { return "" }, "juxonone"); err == nil || runtime != nil {
		t.Fatalf("LoadEnv(invalid prefix) = %#v, %v", runtime, err)
	}
}

func TestLoadEnvBuildsBrowserSessionRuntime(t *testing.T) {
	certFile, keyFile, caFile := writeTestTLSFiles(t)
	values := map[string]string{
		"JUXONONE_BROWSER_ALLOWED_HOSTS_JSON":     `["one.example.com"]`,
		"JUXONONE_BROWSER_SESSION_COOKIE":         "__Host-juxonone_session",
		"JUXONONE_EXTERNAL_ORIGIN":                "https://one.example.com",
		"JUXONONE_SESSION_RESOLVER_ENDPOINT":      "https://account.example.com/internal/session/resolve",
		"JUXONONE_SESSION_RESOLVER_SERVICE":       "juxonone",
		"JUXONONE_SESSION_RESOLVER_TLS_CERT_FILE": certFile,
		"JUXONONE_SESSION_RESOLVER_TLS_KEY_FILE":  keyFile,
		"JUXONONE_SESSION_RESOLVER_CA_FILE":       caFile,
	}
	runtime, err := LoadEnv(func(key string) string { return values[key] }, "JUXONONE")
	if err != nil {
		t.Fatalf("LoadEnv() error = %v", err)
	}
	defer runtime.Close()
	if runtime.Origin() != "https://one.example.com" || runtime.CompanyIdentityResolver() == nil || runtime.RouterOption() == nil {
		t.Fatalf("LoadEnv() returned an incomplete runtime")
	}
	if runtime.transport.Proxy != nil || runtime.transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("resolver transport does not enforce its proxy and TLS policy")
	}
	for key, value := range values {
		t.Run("missing "+key, func(t *testing.T) {
			values[key] = ""
			defer func() { values[key] = value }()
			got, err := LoadEnv(func(name string) string { return values[name] }, "JUXONONE")
			if got != nil || !errors.Is(err, auth.ErrAuthBackendUnavailable) || !strings.Contains(err.Error(), key) {
				t.Fatal("missing deployment key did not fail closed with a safe diagnostic")
			}
		})
	}
	t.Run("multiple hosts keep exact origins", func(t *testing.T) {
		previous := values["JUXONONE_BROWSER_ALLOWED_HOSTS_JSON"]
		values["JUXONONE_BROWSER_ALLOWED_HOSTS_JSON"] = `["one.example.com","alias.example.com:8443"]`
		defer func() { values["JUXONONE_BROWSER_ALLOWED_HOSTS_JSON"] = previous }()
		runtime, err := LoadEnv(func(key string) string { return values[key] }, "JUXONONE")
		if err != nil {
			t.Fatal(err)
		}
		defer runtime.Close()
		router := server.NewRouter("/v1/", runtime.RouterOption())
		for _, test := range []struct {
			host, origin string
			status       int
		}{
			{"one.example.com", "https://one.example.com", 204},
			{"alias.example.com:8443", "https://alias.example.com:8443", 204},
			{"alias.example.com:8443", "https://one.example.com", 403},
			{"alias.example.com:8443", "http://alias.example.com:8443", 403},
			{"unknown.example.com", "https://unknown.example.com", 403},
			{"one.example.com:443", "https://one.example.com", 403},
		} {
			request := httptest.NewRequest(http.MethodOptions, "http://"+test.host+"/v1/resource", nil)
			request.Header.Set("Origin", test.origin)
			request.Header.Set("Access-Control-Request-Method", "POST")
			request.Header.Set("Access-Control-Request-Headers", "X-CSRF-Token")
			recorder := httptest.NewRecorder()
			router.GinEngine().ServeHTTP(recorder, request)
			if recorder.Code != test.status {
				t.Fatalf("%s / %s = %d, want %d", test.host, test.origin, recorder.Code, test.status)
			}
			if test.status == 204 && (recorder.Header().Get("Access-Control-Allow-Origin") != test.origin || recorder.Header().Get("Access-Control-Allow-Credentials") != "true") {
				t.Fatal("preflight lost exact origin or credentials")
			}
		}
	})
	t.Run("internal requests retain route authentication", func(t *testing.T) {
		router := server.NewRouter("/v1/", runtime.RouterOption())
		workerCalls := 0
		router.Post("worker", gin.HandlerFunc(func(ctx *gin.Context) {
			workerCalls++
			if ctx.GetHeader("Authorization") != "Bearer test-workload-credential" {
				ctx.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			ctx.Status(http.StatusNoContent)
		}))
		router.PRequireBrowserSession("browser", gin.HandlerFunc(func(ctx *gin.Context) { t.Fatal("unknown browser Host reached business handler") }))
		router.PRequireBearer("bearer", gin.HandlerFunc(func(ctx *gin.Context) { t.Fatal("missing Bearer reached business handler") }))
		for _, test := range []struct {
			name, path, host, authorization string
			origins                         []string
			status, calls                   int
		}{
			{name: "internal worker host", path: "worker", host: "juxonone-api:8080", authorization: "Bearer test-workload-credential", status: http.StatusNoContent, calls: 1},
			{name: "unknown worker host", path: "worker", host: "unknown.example.com", authorization: "Bearer test-workload-credential", status: http.StatusNoContent, calls: 1},
			{name: "worker rejects missing credentials", path: "worker", host: "juxonone-api:8080", status: http.StatusUnauthorized, calls: 1},
			{name: "unknown host with origin", path: "worker", host: "unknown.example.com", origins: []string{"https://one.example.com"}, status: http.StatusForbidden},
			{name: "empty origin is not absent", path: "worker", host: "juxonone-api:8080", origins: []string{""}, status: http.StatusForbidden},
			{name: "unknown browser host", path: "browser", host: "unknown.example.com", status: http.StatusUnauthorized},
			{name: "internal browser host", path: "browser", host: "juxonone-api:8080", status: http.StatusUnauthorized},
			{name: "internal bearer remains protected", path: "bearer", host: "juxonone-api:8080", status: http.StatusUnauthorized},
		} {
			t.Run(test.name, func(t *testing.T) {
				before := workerCalls
				request := httptest.NewRequest(http.MethodPost, "http://"+test.host+"/v1/"+test.path, nil)
				if test.authorization != "" {
					request.Header.Set("Authorization", test.authorization)
				}
				for _, origin := range test.origins {
					request.Header.Add("Origin", origin)
				}
				recorder := httptest.NewRecorder()
				router.GinEngine().ServeHTTP(recorder, request)
				if recorder.Code != test.status || workerCalls-before != test.calls {
					t.Fatalf("status/calls = %d/%d, want %d/%d", recorder.Code, workerCalls-before, test.status, test.calls)
				}
				if len(test.origins) == 0 && !strings.Contains(recorder.Header().Get("Vary"), "Origin") {
					t.Fatal("no-Origin response lost Vary")
				}
				if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
					t.Fatal("internal or denied response exposed CORS origin")
				}
			})
		}
	})
	t.Run("origin must be canonical and registered", func(t *testing.T) {
		previous := values["JUXONONE_EXTERNAL_ORIGIN"]
		defer func() { values["JUXONONE_EXTERNAL_ORIGIN"] = previous }()
		for _, origin := range []string{"https://other.example.com", "https://one.example.com/path", "https://one.example.com?", "HTTPS://one.example.com"} {
			values["JUXONONE_EXTERNAL_ORIGIN"] = origin
			runtime, err := LoadEnv(func(key string) string { return values[key] }, "JUXONONE")
			if runtime != nil || !errors.Is(err, auth.ErrAuthBackendUnavailable) {
				t.Fatalf("invalid origin accepted: %q", origin)
			}
		}
	})
	t.Run("certificate failure is redacted", func(t *testing.T) {
		values["JUXONONE_SESSION_RESOLVER_TLS_KEY_FILE"] = "/private/DO_NOT_LOG/key.pem"
		got, err := LoadEnv(func(name string) string { return values[name] }, "JUXONONE")
		if got != nil || !errors.Is(err, auth.ErrAuthBackendUnavailable) || strings.Contains(err.Error(), "DO_NOT_LOG") {
			t.Fatal("certificate failure was not redacted")
		}
	})
}

// writeTestTLSFiles creates a matching client certificate, private key, and CA bundle.
func writeTestTLSFiles(t *testing.T) (string, string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "juxonone-test-client"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:         true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certFile := filepath.Join(directory, "client.crt")
	keyFile := filepath.Join(directory, "client.key")
	caFile := filepath.Join(directory, "ca.crt")
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	if err := os.WriteFile(certFile, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caFile, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, caFile
}
