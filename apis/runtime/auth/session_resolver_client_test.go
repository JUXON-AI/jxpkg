package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type resolverRoundTripFunc func(*http.Request) (*http.Response, error)

func (function resolverRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func resolverResponse(status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func validResolverResponse(t *testing.T) string {
	t.Helper()
	hash := sha256.Sum256([]byte("csrf"))
	document, err := json.Marshal(sessionResolveWireResponse{
		UserID: 11, UIN: 12, CompanyID: 13, MembershipEpoch: 14,
		Host: "app.example.com", ClientID: "juxonone-web", SessionVersion: 15,
		AuthenticatedAt: 1_700_000_000, IdleExpiresAt: 1_700_000_600,
		AbsoluteExpiresAt: 1_700_003_600,
		CSRFTokenHash:     base64.RawURLEncoding.EncodeToString(hash[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(document)
}

func newResolverClient(t *testing.T, transport http.RoundTripper, timeout time.Duration) *InternalSessionResolverClient {
	t.Helper()
	client, err := NewInternalSessionResolverClient(SessionResolverClientOptions{
		Endpoint: "https://account.internal" + InternalSessionResolvePath,
		Service:  "juxonone", Transport: transport, Timeout: timeout,
	})
	if err != nil {
		t.Fatalf("NewInternalSessionResolverClient() error = %v", err)
	}
	return client
}

func TestInternalSessionResolverClientResolve(t *testing.T) {
	var calls int
	client := newResolverClient(t, resolverRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != http.MethodPost || request.URL.String() != "https://account.internal/internal/session/resolve" {
			t.Fatalf("request = %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" || request.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("headers = %#v", request.Header)
		}
		var body sessionResolveWireRequest
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body != (sessionResolveWireRequest{Host: "app.example.com", Service: "juxonone", SessionID: "opaque-sid"}) {
			t.Fatalf("body = %#v", body)
		}
		return resolverResponse(http.StatusOK, "application/json; charset=utf-8", validResolverResponse(t)), nil
	}), time.Second)

	principal, err := client.Resolve(context.Background(), SessionResolveRequest{
		Host: "app.example.com", Service: "juxonone", SessionID: "opaque-sid",
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if calls != 1 || principal.Claims.UserID != 11 || principal.Claims.UIN != 12 || principal.Claims.CompanyID != 13 ||
		principal.Claims.MembershipEpoch != 14 || principal.Host != "app.example.com" || principal.ClientID != "juxonone-web" ||
		principal.SessionVersion != 15 || len(principal.CSRFTokenHash) != sha256.Size {
		t.Fatalf("calls = %d, principal = %#v", calls, principal)
	}
}

func TestInternalSessionResolverClientRejectsLocalTupleBeforeTransport(t *testing.T) {
	calls := 0
	client := newResolverClient(t, resolverRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("must not be called")
	}), time.Second)
	tests := []SessionResolveRequest{
		{Host: "app.example.com", Service: "other", SessionID: "sid"},
		{Host: "APP.example.com", Service: "juxonone", SessionID: "sid"},
		{Host: "app.example.com.", Service: "juxonone", SessionID: "sid"},
		{Host: "app.example.com:", Service: "juxonone", SessionID: "sid"},
		{Host: "app.example.com:0443", Service: "juxonone", SessionID: "sid"},
		{Host: "127.0.0.1.1", Service: "juxonone", SessionID: "sid"},
		{Host: "app.example.com/path", Service: "juxonone", SessionID: "sid"},
		{Host: "app.example.com", Service: "juxonone", SessionID: ""},
		{Host: "app.example.com", Service: "juxonone", SessionID: " sid"},
		{Host: "app.example.com", Service: "juxonone", SessionID: strings.Repeat("a", maximumOpaqueSessionIDBytes+1)},
	}
	for _, request := range tests {
		if _, err := client.Resolve(context.Background(), request); !errors.Is(err, ErrInvalidCredential) {
			t.Fatalf("Resolve(%#v) error = %v, want ErrInvalidCredential", request, err)
		}
	}
	if calls != 0 {
		t.Fatalf("transport calls = %d, want 0", calls)
	}
}

func TestInternalSessionResolverClientStatusMapping(t *testing.T) {
	for _, test := range []struct {
		name        string
		status      int
		want        error
		contentType string
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, want: ErrInvalidCredential},
		{name: "not found", status: http.StatusNotFound, want: ErrInvalidCredential},
		{name: "bad request", status: http.StatusBadRequest, want: ErrAuthBackendUnavailable},
		{name: "forbidden caller", status: http.StatusForbidden, want: ErrAuthBackendUnavailable},
		{name: "rate limited", status: http.StatusTooManyRequests, want: ErrAuthBackendUnavailable},
		{name: "server unavailable", status: http.StatusServiceUnavailable, want: ErrAuthBackendUnavailable},
		{name: "redirect", status: http.StatusTemporaryRedirect, want: ErrAuthBackendUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newResolverClient(t, resolverRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return resolverResponse(test.status, "text/plain", "opaque error"), nil
			}), time.Second)
			_, err := client.Resolve(context.Background(), SessionResolveRequest{Host: "app.example.com", Service: "juxonone", SessionID: "secret-sid"})
			if !errors.Is(err, test.want) {
				t.Fatalf("Resolve() error = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), "secret-sid") || strings.Contains(err.Error(), "opaque error") {
				t.Fatalf("Resolve() leaked credential or response body: %v", err)
			}
		})
	}
}

func TestInternalSessionResolverClientRejectsMalformedResponses(t *testing.T) {
	valid := validResolverResponse(t)
	hash := base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size))
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "wrong content type", contentType: "text/plain", body: valid},
		{name: "malformed JSON", contentType: "application/json", body: `{"user_id":`},
		{name: "duplicate member", contentType: "application/json", body: `{"user_id":11,"user_id":12}`},
		{name: "unknown member", contentType: "application/json", body: strings.TrimSuffix(valid, "}") + `,"extra":true}`},
		{name: "trailing value", contentType: "application/json", body: valid + `{}`},
		{name: "oversize", contentType: "application/json", body: strings.Repeat(" ", maximumSessionResolveResponseBytes+1)},
		{name: "bad csrf hash", contentType: "application/json", body: strings.Replace(valid, sessionResolveHash(t), "short", 1)},
		{name: "host mismatch", contentType: "application/json", body: strings.Replace(valid, `"host":"app.example.com"`, `"host":"other.example.com"`, 1)},
		{name: "invalid identity", contentType: "application/json", body: strings.Replace(valid, `"user_id":11`, `"user_id":0`, 1)},
		{name: "invalid time order", contentType: "application/json", body: strings.Replace(valid, `"idle_expires_at":1700000600`, `"idle_expires_at":1800000000`, 1)},
		{name: "noncanonical csrf", contentType: "application/json", body: strings.Replace(valid, sessionResolveHash(t), hash+"=", 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newResolverClient(t, resolverRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return resolverResponse(http.StatusOK, test.contentType, test.body), nil
			}), time.Second)
			_, err := client.Resolve(context.Background(), SessionResolveRequest{Host: "app.example.com", Service: "juxonone", SessionID: "sid"})
			if !errors.Is(err, ErrAuthBackendUnavailable) {
				t.Fatalf("Resolve() error = %v, want ErrAuthBackendUnavailable", err)
			}
		})
	}
}

func sessionResolveHash(t *testing.T) string {
	t.Helper()
	hash := sha256.Sum256([]byte("csrf"))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func TestInternalSessionResolverClientTransportFailureAndTimeout(t *testing.T) {
	t.Run("transport failure", func(t *testing.T) {
		client := newResolverClient(t, resolverRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		}), time.Second)
		_, err := client.Resolve(context.Background(), SessionResolveRequest{Host: "app.example.com", Service: "juxonone", SessionID: "sid"})
		if !errors.Is(err, ErrAuthBackendUnavailable) {
			t.Fatalf("Resolve() error = %v", err)
		}
	})
	t.Run("client timeout", func(t *testing.T) {
		client := newResolverClient(t, resolverRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			<-request.Context().Done()
			return nil, request.Context().Err()
		}), 10*time.Millisecond)
		_, err := client.Resolve(context.Background(), SessionResolveRequest{Host: "app.example.com", Service: "juxonone", SessionID: "sid"})
		if !errors.Is(err, ErrAuthBackendUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Resolve() error = %v, want backend unavailable plus deadline", err)
		}
	})
	t.Run("caller cancellation", func(t *testing.T) {
		var once sync.Once
		started := make(chan struct{})
		client := newResolverClient(t, resolverRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			once.Do(func() { close(started) })
			<-request.Context().Done()
			return nil, request.Context().Err()
		}), time.Second)
		ctx, cancel := context.WithCancel(context.Background())
		go func() { <-started; cancel() }()
		_, err := client.Resolve(ctx, SessionResolveRequest{Host: "app.example.com", Service: "juxonone", SessionID: "sid"})
		if !errors.Is(err, ErrAuthBackendUnavailable) || !errors.Is(err, context.Canceled) {
			t.Fatalf("Resolve() error = %v, want backend unavailable plus cancellation", err)
		}
	})
}

func TestNewInternalSessionResolverClientRejectsUnsafeConfiguration(t *testing.T) {
	transport := resolverRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil })
	tests := []SessionResolverClientOptions{
		{},
		{Endpoint: "http://account.internal/internal/session/resolve", Service: "juxonone", Transport: transport, Timeout: time.Second},
		{Endpoint: "https://account.internal/other", Service: "juxonone", Transport: transport, Timeout: time.Second},
		{Endpoint: "https://account.internal/internal/session/resolve?next=x", Service: "juxonone", Transport: transport, Timeout: time.Second},
		{Endpoint: "https://ACCOUNT.internal/internal/session/resolve", Service: "juxonone", Transport: transport, Timeout: time.Second},
		{Endpoint: "https://account.internal./internal/session/resolve", Service: "juxonone", Transport: transport, Timeout: time.Second},
		{Endpoint: "https://account.internal:0443/internal/session/resolve", Service: "juxonone", Transport: transport, Timeout: time.Second},
		{Endpoint: "https://account.internal/internal/session/resolve", Service: " juxonone", Transport: transport, Timeout: time.Second},
		{Endpoint: "https://account.internal/internal/session/resolve", Service: "Juxonone", Transport: transport, Timeout: time.Second},
		{Endpoint: "https://account.internal/internal/session/resolve", Service: "juxonone", Timeout: time.Second},
		{Endpoint: "https://account.internal/internal/session/resolve", Service: "juxonone", Transport: transport},
	}
	for _, options := range tests {
		if _, err := NewInternalSessionResolverClient(options); !errors.Is(err, ErrAuthBackendUnavailable) {
			t.Fatalf("NewInternalSessionResolverClient(%#v) error = %v", options, err)
		}
	}
}
