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

const emptySnapshotBody = `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[]}`

func TestSlowShortTTLTokenIsNotReused(t *testing.T) {
	start := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(start)
	transport := &memoryRoundTripper{clock: clock}
	transport.tokenHandler = func(call int32) memoryResponse {
		if call == 1 {
			clock.Advance(8 * time.Second)
			return tokenResponseFor(10, "expired-token")
		}
		return tokenResponseFor(10, "fresh-token")
	}
	transport.snapshotHandler = func(int32, *http.Request) memoryResponse {
		return successfulSnapshotResponse()
	}
	client := newMemoryClient(t, transport, clock)

	if _, err := client.Snapshot(context.Background(), "org-1", nil, Options{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("first Snapshot() error = %v, want ErrUnavailable", err)
	}
	assertTokenCacheEmpty(t, client)
	if tokenCalls, snapshotCalls := transport.tokenCalls.Load(), transport.snapshotCalls.Load(); tokenCalls != 1 || snapshotCalls != 0 {
		t.Fatalf("first token calls = %d, snapshot calls = %d; want 1/0", tokenCalls, snapshotCalls)
	}

	clock.Set(start.Add(11 * time.Second))
	snapshot, err := client.Snapshot(context.Background(), "org-1", nil, Options{})
	if err != nil {
		t.Fatalf("second Snapshot() error = %v", err)
	}
	if snapshot.Organization.ID != "org-1" {
		t.Fatalf("second Snapshot() organization = %#v", snapshot.Organization)
	}
	if tokenCalls, snapshotCalls := transport.tokenCalls.Load(), transport.snapshotCalls.Load(); tokenCalls != 2 || snapshotCalls != 1 {
		t.Fatalf("second token calls = %d, snapshot calls = %d; want 2/1", tokenCalls, snapshotCalls)
	}
	if auth := transport.snapshotAuthorization(0); auth != "Bearer fresh-token" {
		t.Fatalf("second Snapshot() authorization = %q, want fresh token", auth)
	}
}

func TestConsumedTokenBoundNeverCachesOrCallsDirectory(t *testing.T) {
	for _, delay := range []time.Duration{10 * time.Second, 12 * time.Second} {
		t.Run(delay.String(), func(t *testing.T) {
			start := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
			clock := newFakeClock(start)
			transport := &memoryRoundTripper{clock: clock}
			transport.tokenHandler = func(int32) memoryResponse {
				clock.Advance(delay)
				return tokenResponseFor(10, "expired-token")
			}
			transport.snapshotHandler = func(int32, *http.Request) memoryResponse {
				return successfulSnapshotResponse()
			}
			client := newMemoryClient(t, transport, clock)

			if _, err := client.Snapshot(context.Background(), "org-1", nil, Options{}); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Snapshot() error = %v, want ErrUnavailable", err)
			}
			assertTokenCacheEmpty(t, client)
			if tokenCalls, snapshotCalls := transport.tokenCalls.Load(), transport.snapshotCalls.Load(); tokenCalls != 1 || snapshotCalls != 0 {
				t.Fatalf("token calls = %d, snapshot calls = %d; want 1/0", tokenCalls, snapshotCalls)
			}
		})
	}
}

func TestConsumedRefreshErrorIsSharedByWaiters(t *testing.T) {
	start := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(start)
	tokenStarted := make(chan struct{})
	releaseToken := make(chan struct{})
	transport := &memoryRoundTripper{clock: clock}
	transport.tokenHandler = func(call int32) memoryResponse {
		if call == 1 {
			close(tokenStarted)
			<-releaseToken
			clock.Advance(6 * time.Second)
			return tokenResponseFor(10, "expired-token")
		}
		return tokenResponseFor(10, "fresh-token")
	}
	transport.snapshotHandler = func(int32, *http.Request) memoryResponse {
		return successfulSnapshotResponse()
	}
	client := newMemoryClient(t, transport, clock)

	leaderResult := make(chan error, 1)
	go func() {
		_, err := client.Snapshot(context.Background(), "org-1", nil, Options{})
		leaderResult <- err
	}()
	<-tokenStarted

	const waiters = 4
	reachedWait := make(chan struct{}, waiters)
	results := make([]chan error, waiters)
	cancels := make([]context.CancelFunc, waiters)
	for index := range waiters {
		ctx, cancel := context.WithCancel(context.Background())
		waiting := &waitingContext{Context: ctx, reached: reachedWait}
		results[index] = make(chan error, 1)
		cancels[index] = cancel
		go func(result chan<- error) {
			_, err := client.Snapshot(waiting, "org-1", nil, Options{})
			result <- err
		}(results[index])
	}
	for range waiters {
		<-reachedWait
	}

	cancels[0]()
	if err := <-results[0]; !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter error = %v, want ErrUnavailable and context.Canceled", err)
	}

	close(releaseToken)
	if err := <-leaderResult; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("leader error = %v, want ErrUnavailable", err)
	}
	for index := 1; index < waiters; index++ {
		if err := <-results[index]; !errors.Is(err, ErrUnavailable) {
			t.Fatalf("waiter %d error = %v, want ErrUnavailable", index, err)
		}
	}
	cancels[0]()
	for index := 1; index < waiters; index++ {
		cancels[index]()
	}
	assertTokenCacheEmpty(t, client)
	if tokenCalls, snapshotCalls := transport.tokenCalls.Load(), transport.snapshotCalls.Load(); tokenCalls != 1 || snapshotCalls != 0 {
		t.Fatalf("first wave token calls = %d, snapshot calls = %d; want 1/0", tokenCalls, snapshotCalls)
	}

	clock.Set(start.Add(11 * time.Second))
	if _, err := client.Snapshot(context.Background(), "org-1", nil, Options{}); err != nil {
		t.Fatalf("subsequent Snapshot() error = %v", err)
	}
	if tokenCalls, snapshotCalls := transport.tokenCalls.Load(), transport.snapshotCalls.Load(); tokenCalls != 2 || snapshotCalls != 1 {
		t.Fatalf("subsequent token calls = %d, snapshot calls = %d; want 2/1", tokenCalls, snapshotCalls)
	}
}

func TestTokenCacheExpiryUsesRequestStart(t *testing.T) {
	for _, test := range []struct {
		name          string
		expiresIn     int
		responseDelay time.Duration
		cacheLifetime time.Duration
	}{
		{name: "normal TTL", expiresIn: 60, responseDelay: 2 * time.Second, cacheLifetime: 30 * time.Second},
		{name: "short TTL", expiresIn: 10, responseDelay: 4 * time.Second, cacheLifetime: 5 * time.Second},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			start := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
			clock := newFakeClock(start)
			transport := &memoryRoundTripper{clock: clock}
			transport.tokenHandler = func(call int32) memoryResponse {
				clock.Advance(test.responseDelay)
				return tokenResponseFor(test.expiresIn, fmt.Sprintf("token-%d", call))
			}
			transport.snapshotHandler = func(int32, *http.Request) memoryResponse {
				return successfulSnapshotResponse()
			}
			client := newMemoryClient(t, transport, clock)

			if _, err := client.Snapshot(context.Background(), "org-1", nil, Options{}); err != nil {
				t.Fatalf("initial Snapshot() error = %v", err)
			}
			token, tokenTill := readTokenCache(client)
			wantTill := start.Add(test.cacheLifetime)
			if token != "token-1" || !tokenTill.Equal(wantTill) {
				t.Fatalf("initial cache = (%q, %s), want (%q, %s)", token, tokenTill, "token-1", wantTill)
			}

			clock.Set(wantTill.Add(-time.Second))
			if _, err := client.Snapshot(context.Background(), "org-1", nil, Options{}); err != nil {
				t.Fatalf("cached Snapshot() error = %v", err)
			}
			if tokenCalls, snapshotCalls := transport.tokenCalls.Load(), transport.snapshotCalls.Load(); tokenCalls != 1 || snapshotCalls != 2 {
				t.Fatalf("cached token calls = %d, snapshot calls = %d; want 1/2", tokenCalls, snapshotCalls)
			}
			if auth := transport.snapshotAuthorization(1); auth != "Bearer token-1" {
				t.Fatalf("cached Snapshot() authorization = %q, want first token", auth)
			}

			clock.Set(wantTill)
			if _, err := client.Snapshot(context.Background(), "org-1", nil, Options{}); err != nil {
				t.Fatalf("renewed Snapshot() error = %v", err)
			}
			if tokenCalls, snapshotCalls := transport.tokenCalls.Load(), transport.snapshotCalls.Load(); tokenCalls != 2 || snapshotCalls != 3 {
				t.Fatalf("renewed token calls = %d, snapshot calls = %d; want 2/3", tokenCalls, snapshotCalls)
			}
			if auth := transport.snapshotAuthorization(2); auth != "Bearer token-2" {
				t.Fatalf("renewed Snapshot() authorization = %q, want refreshed token", auth)
			}
		})
	}
}

type fakeClock struct {
	mu      sync.Mutex
	current time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{current: start}
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.current
}

func (clock *fakeClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.current = clock.current.Add(duration)
	clock.mu.Unlock()
}

func (clock *fakeClock) Set(current time.Time) {
	clock.mu.Lock()
	clock.current = current
	clock.mu.Unlock()
}

type memoryResponse struct {
	status int
	body   string
}

type memoryRoundTripper struct {
	clock           *fakeClock
	tokenHandler    func(call int32) memoryResponse
	snapshotHandler func(call int32, request *http.Request) memoryResponse
	tokenCalls      atomic.Int32
	snapshotCalls   atomic.Int32

	authMu             sync.Mutex
	snapshotAuthValues []string
}

func (transport *memoryRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	var (
		call     int32
		response memoryResponse
	)
	switch request.URL.Path {
	case tokenPath:
		call = transport.tokenCalls.Add(1)
		if transport.tokenHandler == nil {
			return nil, fmt.Errorf("unexpected token request")
		}
		response = transport.tokenHandler(call)
	case snapshotPath:
		call = transport.snapshotCalls.Add(1)
		transport.authMu.Lock()
		transport.snapshotAuthValues = append(transport.snapshotAuthValues, request.Header.Get("Authorization"))
		transport.authMu.Unlock()
		if transport.snapshotHandler == nil {
			return nil, fmt.Errorf("unexpected snapshot request")
		}
		response = transport.snapshotHandler(call, request)
	default:
		return nil, fmt.Errorf("unexpected request path %q", request.URL.Path)
	}
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode:    response.status,
		Status:        fmt.Sprintf("%d %s", response.status, http.StatusText(response.status)),
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(response.body)),
		ContentLength: int64(len(response.body)),
		Request:       request,
	}, nil
}

func (transport *memoryRoundTripper) snapshotAuthorization(index int) string {
	transport.authMu.Lock()
	defer transport.authMu.Unlock()
	if index < 0 || index >= len(transport.snapshotAuthValues) {
		return ""
	}
	return transport.snapshotAuthValues[index]
}

func newMemoryClient(t *testing.T, transport http.RoundTripper, clock *fakeClock) *Client {
	t.Helper()
	client, err := newTestClient(testConfig("https://directory.example"), transport)
	if err != nil {
		t.Fatalf("newTestClient() error = %v", err)
	}
	client.now = clock.Now
	return client
}

func tokenResponseFor(expiresIn int, token string) memoryResponse {
	return memoryResponse{
		status: http.StatusOK,
		body: fmt.Sprintf(
			`{"access_token":%q,"token_type":"Bearer","expires_in":%d,"scope":"directory:read"}`,
			token,
			expiresIn,
		),
	}
}

func successfulSnapshotResponse() memoryResponse {
	return memoryResponse{status: http.StatusOK, body: emptySnapshotBody}
}

func assertTokenCacheEmpty(t *testing.T, client *Client) {
	t.Helper()
	token, tokenTill := readTokenCache(client)
	if token != "" || !tokenTill.IsZero() {
		t.Fatalf("token cache = (%q, %s), want empty", token, tokenTill)
	}
}

func readTokenCache(client *Client) (string, time.Time) {
	client.tokenMu.Lock()
	defer client.tokenMu.Unlock()
	return client.token, client.tokenTill
}

type waitingContext struct {
	context.Context
	reachedOnce sync.Once
	reached     chan<- struct{}
}

func (ctx *waitingContext) Done() <-chan struct{} {
	ctx.reachedOnce.Do(func() {
		ctx.reached <- struct{}{}
	})
	return ctx.Context.Done()
}
