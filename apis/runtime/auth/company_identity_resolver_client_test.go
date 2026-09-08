package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestInternalSessionResolverClientResolvesCompanyIdentities(t *testing.T) {
	client := newResolverClient(t, resolverRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.String() != "https://account.internal"+InternalCompanyIdentityResolvePath {
			t.Fatalf("request = %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" ||
			request.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("headers = %#v", request.Header)
		}
		var body companyIdentityResolveWireRequest
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Service != "juxonone" || body.CompanyID != 9 || len(body.UINs) != 2 || body.UINs[0] != 4 || body.UINs[1] != 7 {
			t.Fatalf("body = %#v", body)
		}
		return resolverResponse(http.StatusOK, "application/json", `{"company_id":9,"identities":[{"uin":4,"membership_epoch":2,"username":"Owner","avatar_url":"","status":"active","is_company_owner":true},{"uin":7,"membership_epoch":3,"username":"Member","avatar_url":"https://example.com/avatar","status":"disabled","is_company_owner":false}]}`), nil
	}), time.Second)

	identities, err := client.ResolveCompanyIdentities(context.Background(), CompanyIdentityResolveRequest{
		Service: "juxonone", CompanyID: 9, UINs: []uint{4, 7},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 2 || identities[0].UIN != 4 || identities[0].MembershipEpoch != 2 || !identities[0].IsCompanyOwner ||
		identities[1].Status != CompanyIdentityStatusDisabled || identities[1].AvatarURL != "https://example.com/avatar" {
		t.Fatalf("identities = %#v", identities)
	}
}

func TestInternalSessionResolverClientRejectsInvalidCompanyIdentityInputBeforeTransport(t *testing.T) {
	calls := 0
	client := newResolverClient(t, resolverRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("must not be called")
	}), time.Second)
	tests := []CompanyIdentityResolveRequest{
		{Service: "other", CompanyID: 1, UINs: []uint{1}},
		{Service: "juxonone", UINs: []uint{1}},
		{Service: "juxonone", CompanyID: 1},
		{Service: "juxonone", CompanyID: 1, UINs: []uint{0}},
		{Service: "juxonone", CompanyID: 1, UINs: []uint{1, 1}},
		{Service: "juxonone", CompanyID: 1, UINs: make([]uint, maximumCompanyIdentityCount+1)},
	}
	for _, request := range tests {
		if _, err := client.ResolveCompanyIdentities(context.Background(), request); !errors.Is(err, ErrInvalidCredential) {
			t.Fatalf("ResolveCompanyIdentities(%#v) error = %v", request, err)
		}
	}
	if calls != 0 {
		t.Fatalf("transport calls = %d", calls)
	}
}

func TestInternalSessionResolverClientRejectsMalformedCompanyIdentityResponses(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		status      int
	}{
		{name: "wrong status", contentType: "application/json", body: `{}`, status: http.StatusForbidden},
		{name: "wrong content type", contentType: "text/plain", body: `{"company_id":9,"identities":[]}`},
		{name: "wrong company", contentType: "application/json", body: `{"company_id":8,"identities":[]}`},
		{name: "duplicate JSON member", contentType: "application/json", body: `{"company_id":9,"company_id":9,"identities":[]}`},
		{name: "unknown JSON member", contentType: "application/json", body: `{"company_id":9,"identities":[],"extra":true}`},
		{name: "unexpected identity", contentType: "application/json", body: `{"company_id":9,"identities":[{"uin":8,"membership_epoch":1,"username":"x","avatar_url":"","status":"active","is_company_owner":false}]}`},
		{name: "duplicate identity", contentType: "application/json", body: `{"company_id":9,"identities":[{"uin":4,"membership_epoch":1,"username":"x","avatar_url":"","status":"active","is_company_owner":false},{"uin":4,"membership_epoch":1,"username":"x","avatar_url":"","status":"active","is_company_owner":false}]}`},
		{name: "zero epoch", contentType: "application/json", body: `{"company_id":9,"identities":[{"uin":4,"membership_epoch":0,"username":"x","avatar_url":"","status":"active","is_company_owner":false}]}`},
		{name: "unknown status", contentType: "application/json", body: `{"company_id":9,"identities":[{"uin":4,"membership_epoch":1,"username":"x","avatar_url":"","status":"other","is_company_owner":false}]}`},
		{name: "inactive owner", contentType: "application/json", body: `{"company_id":9,"identities":[{"uin":4,"membership_epoch":1,"username":"x","avatar_url":"","status":"disabled","is_company_owner":true}]}`},
		{name: "oversize", contentType: "application/json", body: strings.Repeat(" ", maximumCompanyIdentityResponseBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status := test.status
			if status == 0 {
				status = http.StatusOK
			}
			client := newResolverClient(t, resolverRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return resolverResponse(status, test.contentType, test.body), nil
			}), time.Second)
			_, err := client.ResolveCompanyIdentities(context.Background(), CompanyIdentityResolveRequest{
				Service: "juxonone", CompanyID: 9, UINs: []uint{4, 7},
			})
			if !errors.Is(err, ErrAuthBackendUnavailable) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
