package task

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/JUXON-AI/jxpkg/credits"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWorkerServerRequiresTrustedTLSAndClosesSafely(t *testing.T) {
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "ca.crt")
	if os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600) != nil {
		t.Fatal("write CA")
	}
	makeLeaf := func(name string, serial int64, client bool) (string, string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature}
		if client {
			u, _ := url.Parse(testWorkerCaller("queue").Principal)
			cert.URIs = []*url.URL{u}
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		} else {
			cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certPath, keyPath := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
		for p, b := range map[string][]byte{certPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})} {
			if os.WriteFile(p, b, 0600) != nil {
				t.Fatal("write leaf")
			}
		}
		return certPath, keyPath
	}
	serverCert, serverKey := makeLeaf("server", 2, false)
	clientCert, clientKey := makeLeaf("client", 3, true)
	cfg := WorkerServerConfig{Address: "127.0.0.1:0", CertFile: serverCert, KeyFile: serverKey, ClientCAFile: caFile, Callers: []WorkerCaller{testWorkerCaller("queue")}}
	s, err := NewWorkerServer(cfg, "example", "queue", WorkerConfig{Token: strings.Repeat("x", 32)}, func(context.Context, credits.Subject) (credits.Connection, error) {
		t.Fatal("unexpected acquisition")
		return credits.Connection{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Serve(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	client, err := NewWorkerHTTPClient(credits.TLSConfig{CAFile: caFile, CertFile: clientCert, KeyFile: clientKey}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	plain, err := http.NewRequest("POST", "http://127.0.0.1:1/v1/task", nil)
	if err != nil {
		t.Fatal(err)
	}
	plain.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
	if response, err := client.Do(plain); err == nil {
		response.Body.Close()
		t.Fatal("mTLS client accepted HTTP")
	} else if !strings.Contains(err.Error(), "HTTPS required") {
		t.Fatal("HTTP attempted network access")
	}
	address := "https://" + s.listener.Addr().String() + "/v1/example.GetPendingTask"
	req, err := http.NewRequest("POST", address, strings.NewReader(`{"request":{"task_type":"wrong","worker_id":"worker"}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
	response, err := client.Do(req)
	if err != nil {
		t.Fatal("trusted TLS failed")
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("cross-queue request accepted")
	}
	unsigned := *client
	tr := client.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.Certificates = nil
	unsigned.Transport = tr
	defer unsigned.CloseIdleConnections()
	req, err = http.NewRequest("POST", address, strings.NewReader(`{"request":{"task_type":"queue","worker_id":"worker"}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
	if resp, err := unsigned.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("Bearer without certificate reached handler")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = s.Serve(); err == nil {
		t.Fatal("closed server restarted")
	}
	if _, err = NewWorkerHTTPClient(credits.TLSConfig{CAFile: caFile, CertFile: clientCert, KeyFile: filepath.Join(dir, "missing")}, time.Second); err == nil {
		t.Fatal("missing key accepted")
	}
	if _, err = NewWorkerServer(WorkerServerConfig{Address: ":8444"}, "example", "queue", WorkerConfig{Token: strings.Repeat("x", 32)}, func(context.Context, credits.Subject) (credits.Connection, error) { return credits.Connection{}, nil }); err == nil {
		t.Fatal("missing callers accepted")
	}
}
