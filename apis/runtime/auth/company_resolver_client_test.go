package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestInternalSessionResolverClientCompanyDirectory(t *testing.T) {
	client := newResolverClient(t, resolverRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		switch request.URL.Path {
		case InternalCompanySearchPath:
			if body["service"] != "juxonone" || body["query"] != "目标" {
				t.Fatalf("search body = %#v", body)
			}
			return resolverResponse(http.StatusOK, "application/json", `{"companies":[{"company_id":3,"name":"目标公司"},{"company_id":5,"name":"另一家公司"}]}`), nil
		case InternalCompanyResolvePath:
			return resolverResponse(http.StatusOK, "application/json", `{"company_id":3,"name":"目标公司"}`), nil
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
			return nil, nil
		}
	}), time.Second)

	search, err := client.SearchCompanies(context.Background(), CompanySearchRequest{Query: " 目标 ", Limit: 5})
	if err != nil {
		t.Fatalf("SearchCompanies() error = %v", err)
	}
	if len(search.Companies) != 2 || search.Companies[0].CompanyID != 3 || search.Companies[1].Name != "另一家公司" {
		t.Fatalf("search = %#v", search)
	}
	resolve, err := client.ResolveCompany(context.Background(), CompanyResolveRequest{CompanyID: 3})
	if err != nil {
		t.Fatalf("ResolveCompany() error = %v", err)
	}
	if resolve.CompanyID != 3 || resolve.Name != "目标公司" {
		t.Fatalf("resolve = %#v", resolve)
	}
}

func TestCompanyResolverRejectsInvalidInputAndNotFound(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		run    func(*InternalSessionResolverClient) error
		want   error
	}{
		{"search_limit_overflow", 0, "", func(client *InternalSessionResolverClient) error {
			_, err := client.SearchCompanies(context.Background(), CompanySearchRequest{Query: "目标", Limit: 21})
			return err
		}, ErrInvalidCredential},
		{"search_blank_query", 0, "", func(client *InternalSessionResolverClient) error {
			_, err := client.SearchCompanies(context.Background(), CompanySearchRequest{Query: "  ", Limit: 5})
			return err
		}, ErrInvalidCredential},
		{"search_denied", http.StatusForbidden, "", func(client *InternalSessionResolverClient) error {
			_, err := client.SearchCompanies(context.Background(), CompanySearchRequest{Query: "目标", Limit: 5})
			return err
		}, ErrAuthorizationDenied},
		{"resolve_not_found", http.StatusNotFound, "", func(client *InternalSessionResolverClient) error {
			_, err := client.ResolveCompany(context.Background(), CompanyResolveRequest{CompanyID: 9})
			return err
		}, ErrCompanyNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newResolverClient(t, resolverRoundTripFunc(func(*http.Request) (*http.Response, error) {
				status := test.status
				if status == 0 {
					status = http.StatusOK
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: http.NoBody}, nil
			}), time.Second)
			if err := test.run(client); !errors.Is(err, test.want) {
				t.Fatalf("error = %v want %v", err, test.want)
			}
		})
	}
}

func TestCompanyResolverValidatesResponses(t *testing.T) {
	searchRequest := CompanySearchRequest{Query: "目标", Limit: 5}
	if !ValidCompanySearchResponse(searchRequest, CompanySearchResponse{Companies: []CompanySummary{{CompanyID: 3, Name: "目标公司"}}}) {
		t.Fatal("rejected a valid search response")
	}
	invalidSearches := []CompanySearchResponse{
		{Companies: []CompanySummary{{CompanyID: 3, Name: "目标公司"}, {CompanyID: 3, Name: "重复"}}},
		{Companies: []CompanySummary{{CompanyID: 0, Name: "无 ID"}}},
		{Companies: []CompanySummary{{CompanyID: 3, Name: ""}}},
	}
	for index, response := range invalidSearches {
		if ValidCompanySearchResponse(searchRequest, response) {
			t.Fatalf("accepted invalid search response %d", index)
		}
	}
	if ValidCompanySearchResponse(CompanySearchRequest{Query: "目标", Limit: 1}, CompanySearchResponse{Companies: []CompanySummary{{CompanyID: 3, Name: "a"}, {CompanyID: 5, Name: "b"}}}) {
		t.Fatal("accepted a search response over the requested limit")
	}
	resolveRequest := CompanyResolveRequest{CompanyID: 3}
	if ValidCompanyResolveResponse(resolveRequest, CompanyResolveResponse{CompanyID: 9, Name: "别的公司"}) {
		t.Fatal("accepted a resolve response for another company")
	}
	if !ValidCompanyResolveResponse(resolveRequest, CompanyResolveResponse{CompanyID: 3, Name: "目标公司"}) {
		t.Fatal("rejected a valid resolve response")
	}
}

func TestDecodeCompanyResolverRequests(t *testing.T) {
	search, err := DecodeCompanySearchRequest(strings.NewReader(`{"service":"app","query":" 目标 ","limit":5}`))
	if err != nil || search.Service != "app" || search.Query != "目标" || search.Limit != 5 {
		t.Fatalf("search = %#v err = %v", search, err)
	}
	if _, err := DecodeCompanySearchRequest(strings.NewReader(`{"service":"app","query":"目标","limit":0}`)); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("zero limit error = %v", err)
	}
	if _, err := DecodeCompanySearchRequest(strings.NewReader(`{"service":"app","query":"目标","limit":5,"extra":1}`)); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("unknown field error = %v", err)
	}
	resolve, err := DecodeCompanyResolveRequest(strings.NewReader(`{"service":"app","company_id":3}`))
	if err != nil || resolve.CompanyID != 3 {
		t.Fatalf("resolve = %#v err = %v", resolve, err)
	}
	if _, err := DecodeCompanyResolveRequest(strings.NewReader(`{"service":"app","company_id":0}`)); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("zero company error = %v", err)
	}
	if _, err := DecodeCompanySearchRequest(io.NopCloser(strings.NewReader(`{"service":"app","query":"目标","limit":5}`))); err != nil {
		t.Fatalf("reader error = %v", err)
	}
}
