package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestInternalSessionResolverClientResolvesAuthorizationSubjects(t *testing.T) {
	client := newResolverClient(t, resolverRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != InternalAuthorizationSubjectsResolvePath {
			t.Fatalf("path = %s", request.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(
				`{"company_id":3,"uin":2,"membership_epoch":4,"users":[{"uin":2,"username":"测试成员"}],"departments":[{"id":7,"name":"研发部","path":"/7"}]}`,
			)),
		}, nil
	}), time.Second)
	result, err := client.ResolveAuthorizationSubjects(context.Background(), AuthorizationSubjectsResolveRequest{
		CompanyID: 3, UIN: 2, MembershipEpoch: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Users) != 1 || len(result.Departments) != 1 || result.Departments[0].Path != "/7" {
		t.Fatalf("result = %#v", result)
	}
}

func TestAuthorizationSubjectsRejectsMismatchedScopeAndDenial(t *testing.T) {
	client := newResolverClient(t, resolverRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden, Header: make(http.Header), Body: http.NoBody}, nil
	}), time.Second)
	request := AuthorizationSubjectsResolveRequest{CompanyID: 3, UIN: 2, MembershipEpoch: 4}
	if _, err := client.ResolveAuthorizationSubjects(context.Background(), request); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("error = %v", err)
	}
	if ValidAuthorizationSubjectsResponse(request, AuthorizationSubjectsResolveResponse{
		CompanyID: 9, UIN: 2, MembershipEpoch: 4, Users: []AuthorizationUser{}, Departments: []AuthorizationSubjectDepartment{},
	}) {
		t.Fatal("accepted a response from another company")
	}
}
