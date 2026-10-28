package logtodirectory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenResponseValidation(t *testing.T) {
	for _, test := range []struct {
		name           string
		body           string
		statusOverride int
		want           error
	}{
		{name: "wrong scope", body: `{"access_token":"m2m-token","token_type":"Bearer","expires_in":3600,"scope":"profile read"}`, want: ErrProtocol},
		{name: "null scope", body: `{"access_token":"m2m-token","token_type":"Bearer","expires_in":3600,"scope":null}`, want: ErrProtocol},
		{name: "null access token", body: `{"access_token":null,"token_type":"Bearer","expires_in":3600,"scope":"directory:read"}`, want: ErrProtocol},
		{name: "null token type", body: `{"access_token":"m2m-token","token_type":null,"expires_in":3600,"scope":"directory:read"}`, want: ErrProtocol},
		{name: "null expiry", body: `{"access_token":"m2m-token","token_type":"Bearer","expires_in":null,"scope":"directory:read"}`, want: ErrProtocol},
		{name: "unknown audience field", body: `{"access_token":"m2m-token","token_type":"Bearer","expires_in":3600,"scope":"directory:read","audience":"other"}`, want: ErrProtocol},
		{name: "wrong token type", body: `{"access_token":"m2m-token","token_type":"Basic","expires_in":3600,"scope":"directory:read"}`, want: ErrProtocol},
		{name: "expiry too long", body: `{"access_token":"m2m-token","token_type":"Bearer","expires_in":3601,"scope":"directory:read"}`, want: ErrProtocol},
		{name: "expiry zero", body: `{"access_token":"m2m-token","token_type":"Bearer","expires_in":0,"scope":"directory:read"}`, want: ErrProtocol},
		{name: "empty token", body: `{"access_token":"","token_type":"Bearer","expires_in":3600,"scope":"directory:read"}`, want: ErrProtocol},
		{name: "trailing value", body: `{"access_token":"m2m-token","token_type":"Bearer","expires_in":3600,"scope":"directory:read"} {}`, want: ErrProtocol},
		{name: "denied", body: `{"error":"denied"}`, want: ErrDenied, statusOverride: http.StatusUnauthorized},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				status := test.statusOverride
				if status == 0 {
					status = http.StatusOK
				}
				writeJSON(response, status, test.body)
			}))
			if _, err := client.Snapshot(context.Background(), "org-1", []string{"user-1"}, Options{}); !errors.Is(err, test.want) {
				t.Fatalf("Snapshot() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSnapshotResponseStatusContentTypeAndJSONHandling(t *testing.T) {
	for _, test := range []struct {
		name        string
		status      int
		contentType string
		body        string
		want        error
	}{
		{name: "wrong content type", status: http.StatusOK, contentType: "text/plain", body: `{}`, want: ErrProtocol},
		{name: "missing content type", status: http.StatusOK, body: `{}`, want: ErrProtocol},
		{name: "trailing value", status: http.StatusOK, contentType: "application/json", body: `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[]} null`, want: ErrProtocol},
		{name: "unknown top-level field", status: http.StatusOK, contentType: "application/json", body: `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[],"extra":true}`, want: ErrProtocol},
		{name: "unauthorized", status: http.StatusUnauthorized, contentType: "application/json", body: `{"error":"unauthorized"}`, want: ErrDenied},
		{name: "forbidden", status: http.StatusForbidden, contentType: "application/json", body: `{"error":"forbidden"}`, want: ErrDenied},
		{name: "not found", status: http.StatusNotFound, contentType: "application/json", body: `{"error":"not_found"}`, want: ErrDenied},
		{name: "unavailable", status: http.StatusServiceUnavailable, contentType: "application/json", body: `{"error":"unavailable"}`, want: ErrUnavailable},
		{name: "invalid request", status: http.StatusBadRequest, contentType: "application/json", body: `{"error":"invalid_request"}`, want: ErrProtocol},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path == tokenPath {
					writeToken(response)
					return
				}
				if test.contentType != "" {
					response.Header().Set("Content-Type", test.contentType)
				}
				response.WriteHeader(test.status)
				_, _ = io.WriteString(response, test.body)
			}))
			if _, err := client.Snapshot(context.Background(), "org-1", []string{"user-1"}, Options{}); !errors.Is(err, test.want) {
				t.Fatalf("Snapshot() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSnapshotRejectsRedirectWithoutFollowing(t *testing.T) {
	var redirected atomic.Int32
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case tokenPath:
			http.Redirect(response, request, "/redirected-token", http.StatusFound)
		case "/redirected-token":
			redirected.Add(1)
			writeToken(response)
		default:
			http.NotFound(response, request)
		}
	}))
	if _, err := client.Snapshot(context.Background(), "org-1", []string{"user-1"}, Options{}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("Snapshot() error = %v, want ErrProtocol", err)
	}
	if redirected.Load() != 0 {
		t.Fatalf("redirect followed %d times", redirected.Load())
	}
}

func TestNewClientWithTransportRequiresHTTPSAndPreservesDefaultProxyPolicy(t *testing.T) {
	transport := &closeTrackingTransport{}
	if _, err := NewClientWithTransport(testConfig("http://logto.example"), transport); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("NewClientWithTransport(http) error = %v, want ErrUnavailable", err)
	}
	if _, err := NewClientWithTransport(testConfig("https://logto.example"), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("NewClientWithTransport(nil) error = %v, want ErrUnavailable", err)
	}
	client, err := NewClientWithTransport(testConfig("https://logto.example"), transport)
	if err != nil {
		t.Fatalf("NewClientWithTransport(https) error = %v", err)
	}
	bounded, ok := client.http.Transport.(*boundedTransport)
	if !ok || bounded.base != transport {
		t.Fatal("NewClientWithTransport() did not retain the trusted transport")
	}

	defaultClient, err := NewClient(testConfig("https://logto.example"))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	bounded, ok = defaultClient.http.Transport.(*boundedTransport)
	if !ok {
		t.Fatalf("NewClient() transport = %T, want *boundedTransport", defaultClient.http.Transport)
	}
	base, ok := bounded.base.(*http.Transport)
	if !ok || base.Proxy != nil {
		t.Fatalf("NewClient() base transport = %T proxyConfigured=%t, want cloned transport without proxy", bounded.base, base.Proxy != nil)
	}
}

func TestBoundedTransportRejectsUnregisteredRequests(t *testing.T) {
	for _, test := range []struct {
		name   string
		method string
		url    string
	}{
		{name: "GET", method: http.MethodGet, url: "https://logto.example" + snapshotPath},
		{name: "unknown path", method: http.MethodPost, url: "https://logto.example/api/workload-directory/unknown"},
		{name: "query", method: http.MethodPost, url: "https://logto.example" + _organizationsPath + "?limit=1"},
		{name: "cross origin", method: http.MethodPost, url: "https://other.example" + _organizationsPath},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := &countingTransport{}
			transport := &boundedTransport{base: base, origin: "https://logto.example"}
			request, err := http.NewRequestWithContext(context.Background(), test.method, test.url, nil)
			if err != nil {
				t.Fatalf("NewRequestWithContext() error = %v", err)
			}
			if _, err := transport.RoundTrip(request); err == nil {
				t.Fatal("RoundTrip() error = nil, want unregistered endpoint rejection")
			}
			if base.calls.Load() != 0 {
				t.Fatalf("base transport calls = %d, want 0", base.calls.Load())
			}
		})
	}
}

func TestCloseForwardsIdleConnectionClosure(t *testing.T) {
	transport := &closeTrackingTransport{}
	client, err := NewClientWithTransport(testConfig("https://logto.example"), transport)
	if err != nil {
		t.Fatalf("NewClientWithTransport() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if transport.closeCalls.Load() != 1 {
		t.Fatalf("CloseIdleConnections calls = %d, want 1", transport.closeCalls.Load())
	}
	if err := client.Close(); err != nil {
		t.Fatalf("repeated Close() error = %v", err)
	}
}

type countingTransport struct {
	calls atomic.Int32
}

func (transport *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	return nil, errors.New("unexpected transport call")
}

type closeTrackingTransport struct {
	countingTransport
	closeCalls atomic.Int32
}

func (transport *closeTrackingTransport) CloseIdleConnections() {
	transport.closeCalls.Add(1)
}

func TestResponseAndRequestBodyLimits(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		var calls atomic.Int32
		client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			calls.Add(1)
			http.Error(response, "unexpected", http.StatusInternalServerError)
		}))
		userIDs := make([]string, maxMembers)
		for index := range userIDs {
			userIDs[index] = fmt.Sprintf("%03d%s", index, strings.Repeat("x", 125))
		}
		if _, err := client.Snapshot(context.Background(), "org-1", userIDs, Options{}); !errors.Is(err, ErrProtocol) {
			t.Fatalf("Snapshot() error = %v, want ErrProtocol", err)
		}
		if calls.Load() != 0 {
			t.Fatalf("HTTP calls = %d, want 0", calls.Load())
		}
	})

	t.Run("token response", func(t *testing.T) {
		client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, strings.Repeat("x", maxTokenBodyBytes+1))
		}))
		if _, err := client.Snapshot(context.Background(), "org-1", []string{"user-1"}, Options{}); !errors.Is(err, ErrProtocol) {
			t.Fatalf("Snapshot() error = %v, want ErrProtocol", err)
		}
	})

	t.Run("snapshot response", func(t *testing.T) {
		client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path == tokenPath {
				writeToken(response)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, strings.Repeat("x", maxSnapshotBodyBytes+1))
		}))
		if _, err := client.Snapshot(context.Background(), "org-1", []string{"user-1"}, Options{}); !errors.Is(err, ErrProtocol) {
			t.Fatalf("Snapshot() error = %v, want ErrProtocol", err)
		}
	})
}

func TestExpiredTokenRefreshAndNoMemberCache(t *testing.T) {
	var tokenCalls, snapshotCalls atomic.Int32
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == tokenPath {
			tokenCalls.Add(1)
			writeToken(response)
			return
		}
		snapshotCalls.Add(1)
		writeJSON(response, http.StatusOK, `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[]}`)
	}))
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	client.now = func() time.Time { return now }
	for range 2 {
		if _, err := client.Snapshot(context.Background(), "org-1", nil, Options{}); err != nil {
			t.Fatalf("Snapshot() error = %v", err)
		}
	}
	now = now.Add(2 * time.Hour)
	if _, err := client.Snapshot(context.Background(), "org-1", nil, Options{}); err != nil {
		t.Fatalf("Snapshot() after expiry error = %v", err)
	}
	if tokenCalls.Load() != 2 || snapshotCalls.Load() != 3 {
		t.Fatalf("token calls = %d, snapshot calls = %d; want 2/3", tokenCalls.Load(), snapshotCalls.Load())
	}
}

func TestTokenExpirySkew(t *testing.T) {
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == tokenPath {
			writeJSON(response, http.StatusOK, `{"access_token":"m2m-token","token_type":"Bearer","expires_in":60,"scope":"directory:read"}`)
			return
		}
		writeJSON(response, http.StatusOK, `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[]}`)
	}))
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	client.now = func() time.Time { return now }
	if _, err := client.Snapshot(context.Background(), "org-1", nil, Options{}); err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	want := now.Add(30 * time.Second)
	if !client.tokenTill.Equal(want) {
		t.Fatalf("token expiry = %s, want %s", client.tokenTill, want)
	}
}

func TestDependencyFailureIsNotCached(t *testing.T) {
	var tokenCalls, snapshotCalls atomic.Int32
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == tokenPath {
			tokenCalls.Add(1)
			writeToken(response)
			return
		}
		if snapshotCalls.Add(1) == 1 {
			writeJSON(response, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeJSON(response, http.StatusOK, `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[]}`)
	}))
	if _, err := client.Snapshot(context.Background(), "org-1", nil, Options{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("first Snapshot() error = %v, want ErrUnavailable", err)
	}
	if _, err := client.Snapshot(context.Background(), "org-1", nil, Options{}); err != nil {
		t.Fatalf("second Snapshot() error = %v", err)
	}
	if tokenCalls.Load() != 1 || snapshotCalls.Load() != 2 {
		t.Fatalf("token calls = %d, snapshot calls = %d; want 1/2", tokenCalls.Load(), snapshotCalls.Load())
	}
}

func TestConcurrentSnapshotRequestsAreNotSerialized(t *testing.T) {
	var tokenCalls, snapshotCalls atomic.Int32
	firstDataRequest := make(chan struct{})
	secondDataRequest := make(chan struct{})
	releaseFirst := make(chan struct{})
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == tokenPath {
			tokenCalls.Add(1)
			writeToken(response)
			return
		}
		switch snapshotCalls.Add(1) {
		case 1:
			writeJSON(response, http.StatusOK, `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[]}`)
		case 2:
			close(firstDataRequest)
			<-releaseFirst
			writeJSON(response, http.StatusOK, `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[]}`)
		case 3:
			close(secondDataRequest)
			writeJSON(response, http.StatusOK, `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[]}`)
		default:
			http.Error(response, "unexpected snapshot call", http.StatusInternalServerError)
		}
	}))
	if _, err := client.Snapshot(context.Background(), "org-1", nil, Options{}); err != nil {
		t.Fatalf("prime Snapshot() error = %v", err)
	}

	errs := make(chan error, 2)
	go func() {
		_, err := client.Snapshot(context.Background(), "org-1", nil, Options{})
		errs <- err
	}()
	select {
	case <-firstDataRequest:
	case <-time.After(time.Second):
		t.Fatal("first data request did not start")
	}
	go func() {
		_, err := client.Snapshot(context.Background(), "org-1", nil, Options{})
		errs <- err
	}()
	select {
	case <-secondDataRequest:
	case <-time.After(time.Second):
		t.Fatal("second data request was serialized behind the first")
	}
	close(releaseFirst)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent Snapshot() error = %v", err)
		}
	}
	if tokenCalls.Load() != 1 || snapshotCalls.Load() != 3 {
		t.Fatalf("token calls = %d, snapshot calls = %d; want 1/3", tokenCalls.Load(), snapshotCalls.Load())
	}
}

func TestConcurrentExpiredTokenRefreshIsCoalesced(t *testing.T) {
	var tokenCalls, snapshotCalls atomic.Int32
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == tokenPath {
			if tokenCalls.Add(1) > 1 {
				time.Sleep(50 * time.Millisecond)
			}
			writeToken(response)
			return
		}
		snapshotCalls.Add(1)
		writeJSON(response, http.StatusOK, `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[]}`)
	}))
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	client.now = func() time.Time { return now }
	if _, err := client.Snapshot(context.Background(), "org-1", nil, Options{}); err != nil {
		t.Fatalf("prime Snapshot() error = %v", err)
	}
	now = now.Add(2 * time.Hour)

	const requests = 8
	start := make(chan struct{})
	errs := make(chan error, requests)
	var wait sync.WaitGroup
	wait.Add(requests)
	for range requests {
		go func() {
			defer wait.Done()
			<-start
			_, err := client.Snapshot(context.Background(), "org-1", nil, Options{})
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Snapshot() error = %v", err)
		}
	}
	if tokenCalls.Load() != 2 || snapshotCalls.Load() != int32(requests+1) {
		t.Fatalf("token calls = %d, snapshot calls = %d; want 2/%d", tokenCalls.Load(), snapshotCalls.Load(), requests+1)
	}
}

func TestConcurrentTokenRefreshFailureIsShared(t *testing.T) {
	var tokenCalls, snapshotCalls atomic.Int32
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == tokenPath {
			if tokenCalls.Add(1) == 1 {
				writeToken(response)
				return
			}
			time.Sleep(50 * time.Millisecond)
			writeJSON(response, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		snapshotCalls.Add(1)
		writeJSON(response, http.StatusOK, `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[]}`)
	}))
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	client.now = func() time.Time { return now }
	if _, err := client.Snapshot(context.Background(), "org-1", nil, Options{}); err != nil {
		t.Fatalf("prime Snapshot() error = %v", err)
	}
	now = now.Add(2 * time.Hour)

	const requests = 8
	start := make(chan struct{})
	errs := make(chan error, requests)
	var wait sync.WaitGroup
	wait.Add(requests)
	for range requests {
		go func() {
			defer wait.Done()
			<-start
			_, err := client.Snapshot(context.Background(), "org-1", nil, Options{})
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("concurrent Snapshot() error = %v, want ErrUnavailable", err)
		}
	}
	if tokenCalls.Load() != 2 || snapshotCalls.Load() != 1 {
		t.Fatalf("token calls = %d, snapshot calls = %d; want 2/1", tokenCalls.Load(), snapshotCalls.Load())
	}
}
