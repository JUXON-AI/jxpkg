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

func TestAuthorizedSessionClientUsesOneResolverRequest(t *testing.T) {
	var calls int
	client := newResolverClient(t, resolverRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Path != InternalAuthorizedSessionResolvePath || request.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL)
		}
		input, err := DecodeAuthorizedSessionResolveRequest(request.Body)
		if err != nil || input.Service != "juxonone" || input.Host != "app.example.com" || len(input.Permissions) != 1 {
			t.Fatalf("request = %#v, error = %v", input, err)
		}
		var session SessionResolveResponse
		if err := json.Unmarshal([]byte(validResolverResponse(t)), &session); err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(AuthorizedSessionResolveResponse{
			Session: session,
			Authorization: &AuthorizationContextResolveResponse{
				CompanyID: 13, UIN: 12, MembershipEpoch: 14,
				AllowedPermissions: []PermissionCode{"agent.create"},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return resolverResponse(http.StatusOK, "application/json", string(wire)), nil
	}), time.Second)
	result, err := client.ResolveAuthorized(context.Background(), AuthorizedSessionResolveRequest{
		Host: "app.example.com", Service: "juxonone", SessionID: "opaque-sid", IncludeAuthorization: true, Permissions: []PermissionCode{"agent.create"},
	})
	if err != nil || calls != 1 || result == nil || result.Principal.Claims.UserID != 11 || len(result.Authorization.AllowedPermissions) != 1 {
		t.Fatalf("result = %#v, calls = %d, error = %v", result, calls, err)
	}
}

func TestAuthorizedSessionClientCanResolveWithoutPermissionQueries(t *testing.T) {
	client := newResolverClient(t, resolverRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		input, err := DecodeAuthorizedSessionResolveRequest(request.Body)
		if err != nil || input.IncludeAuthorization || len(input.Permissions) != 0 {
			t.Fatalf("session-only input = %#v, error = %v", input, err)
		}
		return resolverResponse(http.StatusOK, "application/json", `{"session":`+validResolverResponse(t)+`}`), nil
	}), time.Second)
	result, err := client.ResolveAuthorized(context.Background(), AuthorizedSessionResolveRequest{
		Host: "app.example.com", Service: "juxonone", SessionID: "opaque-sid",
	})
	if err != nil || result == nil || result.Principal.Claims.UserID != 11 {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
}

func TestAuthorizedSessionClientRejectsMismatchedServiceBeforeTransport(t *testing.T) {
	var calls int
	client := newResolverClient(t, resolverRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected call")
	}), time.Second)
	_, err := client.ResolveAuthorized(context.Background(), AuthorizedSessionResolveRequest{
		Host: "app.example.com", Service: "other", SessionID: "opaque-sid",
	})
	if !errors.Is(err, ErrInvalidCredential) || calls != 0 {
		t.Fatalf("error = %v, calls = %d", err, calls)
	}
}

func TestDecodeAuthorizedSessionRejectsDuplicatePermission(t *testing.T) {
	_, err := DecodeAuthorizedSessionResolveRequest(strings.NewReader(`{"host":"app.example.com","service":"juxonone","session_id":"opaque-sid","include_authorization":true,"permissions":["agent.create","agent.create"]}`))
	if !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("error = %v", err)
	}
}
