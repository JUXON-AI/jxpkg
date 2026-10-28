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
				case organizationsPath:
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
		{name: "null name", body: `{"organizations":[{"id":"org-1","name":null}]}`, limit: 1, wantErr: true},
		{name: "empty name", body: `{"organizations":[{"id":"org-1","name":""}]}`, limit: 1, wantErr: true},
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
	dataStarted := make(chan struct{}, requests)
	releaseData := make(chan struct{})
	var tokenCalls atomic.Int32
	var dataCalls atomic.Int32
	var headerMu sync.Mutex
	dataRequestIDs := make(map[string]int, requests)
	tokenRequestIDs := make(chan string, 1)

	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case tokenPath:
			tokenCalls.Add(1)
			tokenRequestIDs <- request.Header.Get("X-Request-Id")
			writeToken(response)
		case snapshotPath:
			dataCalls.Add(1)
			headerMu.Lock()
			dataRequestIDs[request.Header.Get("X-Request-Id")]++
			headerMu.Unlock()
			dataStarted <- struct{}{}
			<-releaseData
			fields := decodeRawObject(t, request)
			if _, list := fields["list_members"]; list {
				writeJSON(response, http.StatusOK, `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[],"next_cursor":null}`)
				return
			}
			writeJSON(response, http.StatusOK, emptySnapshotBody)
		case organizationsPath:
			dataCalls.Add(1)
			headerMu.Lock()
			dataRequestIDs[request.Header.Get("X-Request-Id")]++
			headerMu.Unlock()
			dataStarted <- struct{}{}
			<-releaseData
			writeJSON(response, http.StatusOK, `{"organizations":[]}`)
		default:
			http.NotFound(response, request)
		}
	}))

	start := make(chan struct{})
	errs := make(chan error, requests)
	var wait sync.WaitGroup
	wait.Add(requests)
	go func() {
		defer wait.Done()
		<-start
		_, err := client.Snapshot(requestid.WithContext(context.Background(), "request-1"), "org-1", nil, Options{})
		errs <- err
	}()
	go func() {
		defer wait.Done()
		<-start
		_, err := client.Snapshot(requestid.WithContext(context.Background(), "request-2"), "org-1", nil, Options{})
		errs <- err
	}()
	go func() {
		defer wait.Done()
		<-start
		_, _, err := client.ListPage(requestid.WithContext(context.Background(), "request-3"), "org-1", "", 1, Options{})
		errs <- err
	}()
	go func() {
		defer wait.Done()
		<-start
		_, _, err := client.SearchOrganizations(requestid.WithContext(context.Background(), "request-4"), "query", "", 1)
		errs <- err
	}()
	close(start)

	for range requests {
		select {
		case <-dataStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("directory data request was serialized behind another request")
		}
	}
	close(releaseData)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent directory read error = %v", err)
		}
	}
	if tokenCalls.Load() != 1 || dataCalls.Load() != requests {
		t.Fatalf("token calls = %d, data calls = %d; want 1/%d", tokenCalls.Load(), dataCalls.Load(), requests)
	}
	if leaderID := <-tokenRequestIDs; leaderID < "request-1" || leaderID > "request-4" {
		t.Fatalf("token request ID = %q, want one caller context", leaderID)
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
		case organizationsPath:
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
		headers[organizationsPath] != "search-request" {
		t.Fatalf("forwarded request IDs = %v", headers)
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("private transport detail")
}
