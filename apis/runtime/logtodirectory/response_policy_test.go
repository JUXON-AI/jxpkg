package logtodirectory

import (
	"context"
	"errors"
	"net/http"
	"strings"
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
