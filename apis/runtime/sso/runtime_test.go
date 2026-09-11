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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
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

func TestLoadEnvBuildsImmutableBrowserSecurityRuntime(t *testing.T) {
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
	if runtime.Origin() != "https://one.example.com" || runtime.CompanyIdentityResolver() == nil || len(runtime.RouterOptions()) != 2 {
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
