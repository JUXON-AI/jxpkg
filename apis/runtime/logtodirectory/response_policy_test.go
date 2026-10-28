package logtodirectory

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOrganizationDeniedIsOnlyRecognizedFromExactDirectoryJSON(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		tokenDenied bool
		wantSubtype bool
	}{
		{name: "exact organization denial", contentType: "application/json", body: _organizationDeniedBody, wantSubtype: true},
		{name: "generic forbidden", contentType: "application/json", body: `{"error":"forbidden"}`},
		{name: "malformed JSON", contentType: "application/json", body: `{"error":"organization_access_denied"`},
		{name: "extra field", contentType: "application/json", body: `{"error":"organization_access_denied","extra":true}`},
		{name: "null", contentType: "application/json", body: `null`},
		{name: "wrong content type", contentType: "text/plain", body: _organizationDeniedBody},
		{name: "oversize body", contentType: "application/json", body: strings.Repeat("x", _maxErrorBodyBytes+1)},
		{name: "token endpoint exact body", contentType: "application/json", body: _organizationDeniedBody, tokenDenied: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var directoryCalls int
			client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path == tokenPath {
					if test.tokenDenied {
						response.Header().Set("Content-Type", test.contentType)
						response.WriteHeader(http.StatusForbidden)
						_, _ = response.Write([]byte(test.body))
						return
					}
					writeToken(response)
					return
				}
				directoryCalls++
				response.Header().Set("Content-Type", test.contentType)
				response.WriteHeader(http.StatusForbidden)
				_, _ = response.Write([]byte(test.body))
			}))

			_, err := client.Snapshot(context.Background(), "org-1", nil, Options{})
			if !errors.Is(err, ErrDenied) {
				t.Fatalf("Snapshot() error = %v, want ErrDenied", err)
			}
			if got := errors.Is(err, ErrOrganizationDenied); got != test.wantSubtype {
				t.Fatalf("errors.Is(ErrOrganizationDenied) = %t, want %t; error = %v", got, test.wantSubtype, err)
			}
			if errors.Is(err, ErrProtocol) {
				t.Fatalf("Snapshot() error = %v, want denial rather than protocol error", err)
			}
			if test.tokenDenied && directoryCalls != 0 {
				t.Fatalf("directory calls = %d, want 0 after token denial", directoryCalls)
			}
		})
	}
}

func TestUnexpectedStatusClassificationMatrix(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		malformed  bool
		want       error
		wantMarker bool
	}{
		{name: "redirect", status: http.StatusFound, want: ErrProtocol, wantMarker: true},
		{name: "bad request", status: http.StatusBadRequest, want: ErrProtocol, wantMarker: true},
		{name: "payload too large", status: http.StatusRequestEntityTooLarge, want: ErrProtocol, wantMarker: true},
		{name: "unauthorized", status: http.StatusUnauthorized, want: ErrDenied},
		{name: "forbidden", status: http.StatusForbidden, want: ErrDenied},
		{name: "not found token", status: http.StatusNotFound, want: ErrProtocol, wantMarker: true},
		{name: "too many requests", status: http.StatusTooManyRequests, want: ErrUnavailable},
		{name: "service unavailable", status: http.StatusServiceUnavailable, want: ErrUnavailable},
		{name: "malformed success", status: http.StatusOK, malformed: true, want: ErrProtocol},
	}
	for _, surface := range []struct {
		name      string
		failToken bool
	}{
		{name: "token", failToken: true},
		{name: "directory"},
	} {
		for _, test := range tests {
			name := test.name
			want := test.want
			wantMarker := test.wantMarker
			if surface.name == "directory" && test.status == http.StatusNotFound {
				name = "not found directory"
				want = ErrDenied
				wantMarker = false
			}
			t.Run(surface.name+"/"+name, func(t *testing.T) {
				const sensitiveBody = "provider-only-sensitive-body"
				var directoryCalls atomic.Int32
				client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
					isToken := request.URL.Path == tokenPath
					if !isToken {
						directoryCalls.Add(1)
					}
					if isToken && !surface.failToken {
						writeToken(response)
						return
					}
					if test.malformed {
						response.Header().Set("Content-Type", "application/json")
						response.WriteHeader(test.status)
						_, _ = response.Write([]byte(`{"access_token":`))
						return
					}
					writeJSON(response, test.status, `{"error":"`+sensitiveBody+`"}`)
				}))

				_, err := client.Snapshot(context.Background(), "org-1", nil, Options{})
				if !errors.Is(err, want) {
					t.Fatalf("Snapshot() error = %v, want %v", err, want)
				}
				if errors.Is(err, ErrUnexpectedStatus) != wantMarker {
					t.Fatalf("errors.Is(ErrUnexpectedStatus) = %t, want %t; error = %v", errors.Is(err, ErrUnexpectedStatus), wantMarker, err)
				}
				if wantMarker && !errors.Is(err, ErrProtocol) {
					t.Fatalf("Snapshot() marker error = %v, want errors.Is(ErrProtocol)", err)
				}
				if strings.Contains(err.Error(), sensitiveBody) {
					t.Fatalf("Snapshot() exposed provider body: %v", err)
				}
				if wantMarker && err.Error() != ErrUnexpectedStatus.Error() {
					t.Fatalf("Snapshot() marker error = %q, want %q", err, ErrUnexpectedStatus)
				}
				if surface.failToken && directoryCalls.Load() != 0 {
					t.Fatalf("directory calls = %d after token failure, want 0", directoryCalls.Load())
				}
			})
		}
	}
}
