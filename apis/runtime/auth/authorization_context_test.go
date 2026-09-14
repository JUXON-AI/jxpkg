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

func TestInternalSessionResolverClientResolvesAuthorizationContext(t *testing.T) {
	client := newResolverClient(t, resolverRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != InternalAuthorizationContextResolvePath {
			t.Fatalf("path = %s", request.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(
				`{"company_id":3,"uin":2,"membership_epoch":4,"is_company_owner":false,"departments":[{"id":7,"path":"/7"}],"allowed_permissions":["agent.create"]}`,
			)),
		}, nil
	}), time.Second)
	result, err := client.ResolveAuthorizationContext(context.Background(), AuthorizationContextResolveRequest{
		CompanyID: 3, UIN: 2, MembershipEpoch: 4, Permissions: []PermissionCode{"agent.create"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Departments) != 1 || len(result.AllowedPermissions) != 1 {
		t.Fatalf("result = %#v", result)
	}
}

func TestInternalSessionResolverClientNormalizesEmptyAuthorizationPermissions(t *testing.T) {
	client := newResolverClient(t, resolverRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		input, err := DecodeAuthorizationContextResolveRequest(request.Body)
		if err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if input.Permissions == nil || len(input.Permissions) != 0 {
			t.Fatalf("permissions = %#v, want non-nil empty slice", input.Permissions)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(
				`{"company_id":3,"uin":2,"membership_epoch":4,"is_company_owner":false,"departments":[],"allowed_permissions":[]}`,
			)),
		}, nil
	}), time.Second)
	result, err := client.ResolveAuthorizationContext(context.Background(), AuthorizationContextResolveRequest{
		CompanyID: 3, UIN: 2, MembershipEpoch: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || len(result.AllowedPermissions) != 0 {
		t.Fatalf("result = %#v", result)
	}
}

func TestAuthorizationContextRejectsInvalidInputAndDenial(t *testing.T) {
	client := newResolverClient(t, resolverRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden, Header: make(http.Header), Body: http.NoBody}, nil
	}), time.Second)
	if _, err := client.ResolveAuthorizationContext(context.Background(), AuthorizationContextResolveRequest{
		CompanyID: 3, UIN: 2, MembershipEpoch: 4, Permissions: []PermissionCode{"agent.create"},
	}); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("error = %v", err)
	}
	if _, err := client.ResolveAuthorizationContext(context.Background(), AuthorizationContextResolveRequest{
		CompanyID: 3, UIN: 2, MembershipEpoch: 4, Permissions: []PermissionCode{"Agent.Create"},
	}); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("invalid permission error = %v", err)
	}
}

func TestAuthorizationContextAllowsOnlyReturnedPermissions(t *testing.T) {
	result := &AuthorizationContextResolveResponse{AllowedPermissions: []PermissionCode{"agent.create"}}
	if !result.Allows("agent.create") {
		t.Fatal("Allows() rejected an allowed permission")
	}
	if result.Allows("role.create") || (*AuthorizationContextResolveResponse)(nil).Allows("agent.create") {
		t.Fatal("Allows() accepted a permission absent from the resolved context")
	}
}
