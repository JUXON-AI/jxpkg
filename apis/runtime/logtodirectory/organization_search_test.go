package logtodirectory

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/requestid"
)

func TestSearchOrganizationsContractAndOptionalEndCursor(t *testing.T) {
	for _, test := range []struct {
		name   string
		query  string
		cursor string
	}{
		{name: "empty query and omitted cursor", query: ""},
		{name: "provider text and cursor", query: "  组织😀 100%_  ", cursor: "org-1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case tokenPath:
					writeToken(response)
				case _organizationsPath:
					fields := decodeRawObject(t, request)
					assertRawJSON(t, fields, "query", string(mustJSON(t, test.query)))
					assertRawJSON(t, fields, "limit", `100`)
					if test.cursor == "" {
						if _, exists := fields["cursor"]; exists || len(fields) != 2 {
							t.Errorf("request fields = %v, want query and limit only", fields)
						}
					} else {
						assertRawJSON(t, fields, "cursor", string(mustJSON(t, test.cursor)))
						if len(fields) != 3 {
							t.Errorf("request fields = %v, want query, cursor, and limit", fields)
						}
					}
					writeJSON(response, http.StatusOK, `{"organizations":[{"id":"org-2","name":"Company Two"},{"id":"org-3","name":"Company Three"}],"next_cursor":"org-3"}`)
				default:
					http.NotFound(response, request)
				}
			}))

			organizations, next, err := client.SearchOrganizations(context.Background(), test.query, test.cursor, 100)
			if err != nil {
				t.Fatalf("SearchOrganizations() error = %v", err)
			}
			if len(organizations) != 2 || organizations[0] != (Organization{ID: "org-2", Name: "Company Two"}) ||
				organizations[1] != (Organization{ID: "org-3", Name: "Company Three"}) {
				t.Fatalf("SearchOrganizations() organizations = %#v", organizations)
			}
			if next == nil || *next != "org-3" {
				t.Fatalf("SearchOrganizations() next = %v, want org-3", next)
			}
		})
	}
}

func TestSearchOrganizationsOmittedEndCursorIsNil(t *testing.T) {
	for _, body := range []string{
		`{"organizations":[]}`,
		`{"organizations":[{"id":"org-1","name":"Company"}]}`,
	} {
		client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path == tokenPath {
				writeToken(response)
				return
			}
			writeJSON(response, http.StatusOK, body)
		}))
		organizations, next, err := client.SearchOrganizations(context.Background(), "", "", 1)
		if err != nil {
			t.Fatalf("SearchOrganizations() error = %v", err)
		}
		if organizations == nil {
			t.Fatal("SearchOrganizations() organizations = nil, want bounded array")
		}
		if next != nil {
			t.Fatalf("SearchOrganizations() next = %q, want nil", *next)
		}
	}
}

func TestSearchOrganizationsRejectsInvalidInputBeforeHTTP(t *testing.T) {
	var calls atomic.Int32
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		http.Error(response, "unexpected", http.StatusInternalServerError)
	}))
	for _, test := range []struct {
		name   string
		query  string
		cursor string
		limit  int
	}{
		{name: "zero limit", query: "query", limit: 0},
		{name: "oversize limit", query: "query", limit: 101},
		{name: "oversize query", query: strings.Repeat("界", 129), limit: 1},
		{name: "control query", query: "query\x00", limit: 1},
		{name: "invalid UTF-8 query", query: string([]byte{0xff}), limit: 1},
		{name: "empty cursor", query: "query", cursor: "cursor\u0000", limit: 1},
		{name: "oversize cursor", query: "query", cursor: strings.Repeat("c", 22), limit: 1},
		{name: "whitespace cursor", query: "query", cursor: "cursor one", limit: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := client.SearchOrganizations(context.Background(), test.query, test.cursor, test.limit); !errors.Is(err, ErrProtocol) {
				t.Fatalf("SearchOrganizations() error = %v, want ErrProtocol", err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("HTTP calls = %d, want 0", calls.Load())
	}
}

func TestSearchOrganizationsAcceptsProviderInputBoundaries(t *testing.T) {
	for _, test := range []struct {
		name   string
		query  string
		cursor string
		limit  int
	}{
		{name: "query limit", query: strings.Repeat("😀", 128), limit: 100},
		{name: "cursor limit", cursor: strings.Repeat("界", 21), limit: 1},
		{name: "internal and edge spaces", query: "  two words  ", limit: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path == tokenPath {
					writeToken(response)
					return
				}
				writeJSON(response, http.StatusOK, `{"organizations":[]}`)
			}))
			if _, _, err := client.SearchOrganizations(context.Background(), test.query, test.cursor, test.limit); err != nil {
				t.Fatalf("SearchOrganizations() error = %v", err)
			}
		})
	}
}

func TestSearchOrganizationsPreservesProviderLegalNames(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "line feed", value: "Company\nResearch"},
		{name: "carriage return", value: "Company\rResearch"},
		{name: "maximum runes", value: strings.Repeat("界", 128)},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := string(mustJSON(t, map[string]any{
				"organizations": []Organization{{ID: "org-1", Name: test.value}},
			}))
			client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path == tokenPath {
					writeToken(response)
					return
				}
				writeJSON(response, http.StatusOK, body)
			}))
			organizations, next, err := client.SearchOrganizations(context.Background(), "", "", 1)
			if err != nil {
				t.Fatalf("SearchOrganizations() error = %v", err)
			}
			if next != nil || len(organizations) != 1 || organizations[0] != (Organization{ID: "org-1", Name: test.value}) {
				t.Fatalf("SearchOrganizations() organizations = %#v, next = %v", organizations, next)
			}
		})
	}
}

func TestSearchOrganizationsResponseValidation(t *testing.T) {
	organizations100 := make([]Organization, 100)
	for index := range organizations100 {
		organizations100[index] = Organization{ID: fmt.Sprintf("org-%03d", index), Name: "Company"}
	}
	tooMany := append(append([]Organization{}, organizations100...), Organization{ID: "org-100", Name: "Company"})
	tests := []struct {
		name    string
		body    string
		query   string
		cursor  string
		limit   int
		wantErr bool
	}{
		{name: "missing array", body: `{}`, limit: 1, wantErr: true},
		{name: "null array", body: `{"organizations":null}`, limit: 1, wantErr: true},
		{name: "wrong array type", body: `{"organizations":{}}`, limit: 1, wantErr: true},
		{name: "unknown top-level field", body: `{"organizations":[],"extra":true}`, limit: 1, wantErr: true},
		{name: "unknown organization field", body: `{"organizations":[{"id":"org-1","name":"Company","extra":true}]}`, limit: 1, wantErr: true},
		{name: "missing id", body: `{"organizations":[{"name":"Company"}]}`, limit: 1, wantErr: true},
		{name: "missing name", body: `{"organizations":[{"id":"org-1"}]}`, limit: 1, wantErr: true},
		{name: "null name", body: `{"organizations":[{"id":"org-1","name":null}]}`, limit: 1, wantErr: true},
		{name: "empty name", body: `{"organizations":[{"id":"org-1","name":""}]}`, limit: 1, wantErr: true},
		{name: "oversize name", body: string(mustJSON(t, map[string]any{"organizations": []Organization{{ID: "org-1", Name: strings.Repeat("界", 129)}}})), limit: 1, wantErr: true},
		{name: "whitespace id", body: `{"organizations":[{"id":"org 1","name":"Company"}]}`, limit: 1, wantErr: true},
		{name: "oversize id", body: `{"organizations":[{"id":"` + strings.Repeat("o", 22) + `","name":"Company"}]}`, limit: 1, wantErr: true},
		{name: "duplicate id", body: `{"organizations":[{"id":"org-1","name":"One"},{"id":"org-1","name":"Two"}]}`, limit: 2, wantErr: true},
		{name: "unordered", body: `{"organizations":[{"id":"org-2","name":"Two"},{"id":"org-1","name":"One"}]}`, limit: 2, wantErr: true},
		{name: "behind request cursor", body: `{"organizations":[{"id":"org-1","name":"One"}]}`, cursor: "org-1", limit: 1, wantErr: true},
		{name: "over page", body: string(mustJSON(t, map[string]any{"organizations": tooMany})), limit: 100, wantErr: true},
		{name: "null end cursor", body: `{"organizations":[],"next_cursor":null}`, limit: 1, wantErr: true},
		{name: "empty end cursor", body: `{"organizations":[],"next_cursor":""}`, limit: 1, wantErr: true},
		{name: "non-string end cursor", body: `{"organizations":[],"next_cursor":1}`, limit: 1, wantErr: true},
		{name: "oversize end cursor", body: `{"organizations":[],"next_cursor":"` + strings.Repeat("o", 22) + `"}`, limit: 1, wantErr: true},
		{name: "whitespace end cursor", body: `{"organizations":[],"next_cursor":"org 1"}`, limit: 1, wantErr: true},
		{name: "end cursor before result", body: `{"organizations":[{"id":"org-2","name":"Two"}],"next_cursor":"org-1"}`, limit: 2, wantErr: true},
		{name: "end cursor without result", body: `{"organizations":[],"next_cursor":"org-2"}`, limit: 2, wantErr: true},
		{name: "valid bounded page", body: string(mustJSON(t, map[string]any{"organizations": organizations100})), limit: 100},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path == tokenPath {
					writeToken(response)
					return
				}
				writeJSON(response, http.StatusOK, test.body)
			}))
			_, _, err := client.SearchOrganizations(context.Background(), "query", test.cursor, test.limit)
			if test.wantErr && !errors.Is(err, ErrProtocol) {
				t.Fatalf("SearchOrganizations() error = %v, want ErrProtocol", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("SearchOrganizations() error = %v", err)
			}
		})
	}
}

func TestSearchOrganizationsStatusPolicy(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		want   error
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, want: ErrDenied},
		{name: "forbidden", status: http.StatusForbidden, want: ErrDenied},
		{name: "not found", status: http.StatusNotFound, want: ErrDenied},
		{name: "invalid request", status: http.StatusBadRequest, want: ErrProtocol},
		{name: "unavailable", status: http.StatusServiceUnavailable, want: ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path == tokenPath {
					writeToken(response)
					return
				}
				writeJSON(response, test.status, `{"error":"provider-only"}`)
			}))
			_, _, err := client.SearchOrganizations(context.Background(), "query", "", 1)
			if !errors.Is(err, test.want) {
				t.Fatalf("SearchOrganizations() error = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), "provider-only") {
				t.Fatalf("SearchOrganizations() exposed provider body: %v", err)
			}
		})
	}
}

func TestSearchOrganizationsPreservesCancellationAndHidesTransportFailure(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		var calls atomic.Int32
		client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			calls.Add(1)
			http.Error(response, "unexpected", http.StatusInternalServerError)
		}))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _, err := client.SearchOrganizations(ctx, "query", "", 1)
		if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
			t.Fatalf("SearchOrganizations() error = %v, want ErrUnavailable and context.Canceled", err)
		}
		if calls.Load() != 0 {
			t.Fatalf("HTTP calls = %d, want 0", calls.Load())
		}
	})

	t.Run("transport failure", func(t *testing.T) {
		client, err := newTestClient(testConfig("https://directory.example"), failingTransport{})
		if err != nil {
			t.Fatalf("newTestClient() error = %v", err)
		}
		_, _, err = client.SearchOrganizations(context.Background(), "query", "", 1)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("SearchOrganizations() error = %v, want ErrUnavailable", err)
		}
		if strings.Contains(err.Error(), "private transport detail") {
			t.Fatalf("SearchOrganizations() exposed transport detail: %v", err)
		}
	})
}

func TestConcurrentColdDirectoryReadsShareTokenAndRemainParallel(t *testing.T) {
	const requests = 4
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dataStarted := make(chan struct{})
	releaseData := make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseData) })
	var tokenCalls atomic.Int32
	var dataCalls atomic.Int32
	var headerMu sync.Mutex
	dataRequestIDs := make(map[string]int, requests)
	tokenRequestIDs := make(chan string, 1)
	var tokenRequestIDOverflow atomic.Bool

	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case tokenPath:
			tokenCalls.Add(1)
			select {
			case tokenRequestIDs <- request.Header.Get("X-Request-Id"):
			default:
				tokenRequestIDOverflow.Store(true)
			}
			writeToken(response)
		case snapshotPath, _organizationsPath:
			dataCalls.Add(1)
			headerMu.Lock()
			dataRequestIDs[request.Header.Get("X-Request-Id")]++
			headerMu.Unlock()
			select {
			case dataStarted <- struct{}{}:
			case <-releaseData:
				return
			case <-request.Context().Done():
				return
			}
			select {
			case <-releaseData:
			case <-request.Context().Done():
				return
			}
			if request.URL.Path == _organizationsPath {
				writeJSON(response, http.StatusOK, `{"organizations":[]}`)
				return
			}
			fields := decodeRawObject(t, request)
			if _, list := fields["list_members"]; list {
				writeJSON(response, http.StatusOK, `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[],"next_cursor":null}`)
				return
			}
			writeJSON(response, http.StatusOK, emptySnapshotBody)
		default:
			http.NotFound(response, request)
		}
	}))

	errs, callers := startConcurrentColdDirectoryReads(ctx, client)
	registerConcurrentColdCleanup(t, release, callers)

	started := 0
	barrierCtx, cancelBarrier := context.WithTimeout(ctx, 2*time.Second)
	defer cancelBarrier()
	for started < requests {
		select {
		case <-dataStarted:
			started++
		case <-barrierCtx.Done():
			t.Fatalf("directory data request was serialized behind another request: %v", barrierCtx.Err())
		}
	}
	release()
	if err := waitForConcurrentColdReaders(ctx, callers); err != nil {
		t.Fatalf("waiting for concurrent directory reads: %v", err)
	}
	for range requests {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent directory read error = %v", err)
		}
	}
	if tokenCalls.Load() != 1 || dataCalls.Load() != requests {
		t.Fatalf("token calls = %d, data calls = %d; want 1/%d", tokenCalls.Load(), dataCalls.Load(), requests)
	}
	if tokenRequestIDOverflow.Load() {
		t.Fatal("unexpected duplicate token request IDs overflowed the capture channel")
	}
	select {
	case leaderID := <-tokenRequestIDs:
		if leaderID < "request-1" || leaderID > "request-4" {
			t.Fatalf("token request ID = %q, want one caller context", leaderID)
		}
	default:
		t.Fatal("token request ID was not captured")
	}
	headerMu.Lock()
	defer headerMu.Unlock()
	for id := 1; id <= requests; id++ {
		key := fmt.Sprintf("request-%d", id)
		if dataRequestIDs[key] != 1 {
			t.Fatalf("data request ID counts = %v, want each caller once", dataRequestIDs)
		}
	}
}

func TestConcurrentColdDirectoryFailureEndsBoundedAndPreservesCause(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dataStarted := make(chan struct{})
	releaseData := make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseData) })
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case tokenPath:
			writeToken(response)
		case _organizationsPath:
			writeJSON(response, http.StatusServiceUnavailable, `{"error":"injected"}`)
		case snapshotPath:
			select {
			case dataStarted <- struct{}{}:
			case <-releaseData:
				return
			case <-request.Context().Done():
				return
			}
			select {
			case <-releaseData:
			case <-request.Context().Done():
				return
			}
			fields := decodeRawObject(t, request)
			if _, list := fields["list_members"]; list {
				writeJSON(response, http.StatusOK, `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[],"next_cursor":null}`)
				return
			}
			writeJSON(response, http.StatusOK, emptySnapshotBody)
		default:
			http.NotFound(response, request)
		}
	}))

	errs, callers := startConcurrentColdDirectoryReads(ctx, client)
	registerConcurrentColdCleanup(t, release, callers)

	started := 0
	barrierCtx, cancelBarrier := context.WithTimeout(ctx, 2*time.Second)
	defer cancelBarrier()
	for started < 3 {
		select {
		case <-dataStarted:
			started++
		case <-barrierCtx.Done():
			t.Fatalf("three successful reads did not reach the data barrier before the injected failure: %v", barrierCtx.Err())
		}
	}
	release()
	if err := waitForConcurrentColdReaders(ctx, callers); err != nil {
		t.Fatalf("waiting after injected directory failure: %v", err)
	}

	failures := 0
	for range 4 {
		err := <-errs
		switch {
		case err == nil:
		case errors.Is(err, ErrUnavailable):
			failures++
		default:
			t.Errorf("injected directory failure changed to an unexpected error: %v", err)
		}
	}
	if failures != 1 {
		t.Fatalf("injected directory failure count = %d, want 1; original 503 must remain ErrUnavailable", failures)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("injected directory failure cleanup exceeded its context: %v", err)
	}
}

func startConcurrentColdDirectoryReads(ctx context.Context, client *Client) (<-chan error, *sync.WaitGroup) {
	start := make(chan struct{})
	errs := make(chan error, 4)
	var callers sync.WaitGroup
	run := func(id int, request func(context.Context) error) {
		callers.Add(1)
		go func() {
			defer callers.Done()
			<-start
			requestCtx := requestid.WithContext(ctx, fmt.Sprintf("request-%d", id))
			errs <- request(requestCtx)
		}()
	}
	run(1, func(ctx context.Context) error {
		_, err := client.Snapshot(ctx, "org-1", nil, Options{})
		return err
	})
	run(2, func(ctx context.Context) error {
		_, err := client.Snapshot(ctx, "org-1", nil, Options{})
		return err
	})
	run(3, func(ctx context.Context) error {
		_, _, err := client.ListPage(ctx, "org-1", "", 1, Options{})
		return err
	})
	run(4, func(ctx context.Context) error {
		_, _, err := client.SearchOrganizations(ctx, "query", "", 1)
		return err
	})
	close(start)
	return errs, &callers
}

func registerConcurrentColdCleanup(t *testing.T, release func(), callers *sync.WaitGroup) {
	t.Helper()
	t.Cleanup(func() {
		release()
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		if err := waitForConcurrentColdReaders(ctx, callers); err != nil {
			t.Errorf("joining concurrent cold-read callers during cleanup: %v", err)
		}
	})
}

func waitForConcurrentColdReaders(ctx context.Context, callers *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		callers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestDirectoryRequestsForwardContextRequestIDIndividually(t *testing.T) {
	var mu sync.Mutex
	headers := make(map[string]string, 3)
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		headers[request.URL.Path] = request.Header.Get("X-Request-Id")
		mu.Unlock()
		switch request.URL.Path {
		case tokenPath:
			writeToken(response)
		case snapshotPath:
			writeJSON(response, http.StatusOK, emptySnapshotBody)
		case _organizationsPath:
			writeJSON(response, http.StatusOK, `{"organizations":[]}`)
		default:
			http.NotFound(response, request)
		}
	}))

	if _, err := client.Snapshot(requestid.WithContext(context.Background(), "leader-request"), "org-1", nil, Options{}); err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if _, _, err := client.SearchOrganizations(requestid.WithContext(context.Background(), "search-request"), "query", "", 1); err != nil {
		t.Fatalf("SearchOrganizations() error = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if headers[tokenPath] != "leader-request" || headers[snapshotPath] != "leader-request" ||
		headers[_organizationsPath] != "search-request" {
		t.Fatalf("forwarded request IDs = %v", headers)
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("private transport detail")
}
