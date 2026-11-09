package credits

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type adjustRoundTripFunc func(*http.Request) (*http.Response, error)

func (f adjustRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestAdminAdjustUsesRawJSONAndAcceptsApplied(t *testing.T) {
	requestValue := AdminAdjustRequest{OrganizationID: "org-2", UserID: "user-3", OperationID: "op-1", Delta: 50, ActorID: "admin-4", Reason: "beta correction"}
	responseValue := AdminAdjustment{State: AdminAdjustmentApplied, OperationID: requestValue.OperationID, OrganizationID: requestValue.OrganizationID, UserID: requestValue.UserID, Delta: requestValue.Delta, ActorID: requestValue.ActorID, Reason: requestValue.Reason}
	client, err := NewClientWithTransport(Config{Endpoint: "https://credits.example"}, adjustRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != AdminAdjustPath || request.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		var raw map[string]any
		if err := json.NewDecoder(request.Body).Decode(&raw); err != nil {
			t.Fatal(err)
		}
		if _, wrapped := raw["request"]; wrapped || len(raw) != 6 {
			t.Fatalf("request was not flat: %#v", raw)
		}
		body, err := json.Marshal(responseValue)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.AdminAdjust(context.Background(), requestValue)
	if err != nil || result != responseValue {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestAdminAdjustReturnsUnknownWithoutInventingBalance(t *testing.T) {
	requestValue := AdminAdjustRequest{OrganizationID: "org-2", UserID: "user-3", OperationID: "op-2", Delta: -25, ActorID: "admin-4", Reason: "rollback"}
	client, err := NewClientWithTransport(Config{Endpoint: "https://credits.example"}, adjustRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"state":"unknown","operation_id":"op-2","organization_id":"org-2","user_id":"user-3","delta":-25,"actor_id":"admin-4","reason":"rollback"}`))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.AdminAdjust(context.Background(), requestValue)
	if err != nil || result.State != AdminAdjustmentUnknown {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestAdminAdjustmentLookupUsesReadOnlyRoute(t *testing.T) {
	lookup := AdminAdjustLookup{OrganizationID: "org-2", UserID: "user-3", OperationID: "op-3"}
	client, err := NewClientWithTransport(Config{Endpoint: "https://credits.example"}, adjustRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != AdminAdjustResultPath {
			t.Fatalf("path=%s", request.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"state":"dispatching","operation_id":"op-3","organization_id":"org-2","user_id":"user-3","delta":10,"actor_id":"admin-4","reason":"recover"}`))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.GetAdminAdjustment(context.Background(), lookup)
	if err != nil || result.State != AdminAdjustmentDispatching {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestAdminAdjustmentStableTransportErrors(t *testing.T) {
	requestValue := AdminAdjustRequest{OrganizationID: "org-2", UserID: "user-3", OperationID: "op-4", Delta: 10, ActorID: "admin-4", Reason: "conflict"}
	for _, tc := range []struct {
		name   string
		status int
		want   error
	}{{"conflict", http.StatusConflict, ErrConflict}, {"missing", http.StatusNotFound, ErrNotFound}} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewClientWithTransport(Config{Endpoint: "https://credits.example"}, adjustRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = client.AdminAdjust(context.Background(), requestValue); !errors.Is(err, tc.want) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestAdminAdjustValidationRejectsUnsafeInput(t *testing.T) {
	for _, value := range []AdminAdjustRequest{
		{OrganizationID: "org-2", UserID: "user-3", OperationID: "op-5", Delta: 0, ActorID: "admin-4", Reason: "zero"},
		{OrganizationID: "org-2", UserID: "user-3", OperationID: "OP-5", Delta: 1, ActorID: "admin-4", Reason: "uppercase"},
		{OrganizationID: "org-2", UserID: "user-3", OperationID: "op-5", Delta: 1, ActorID: "admin-4", Reason: "line\nbreak"},
		{OrganizationID: "org-2", UserID: "user-3", OperationID: "op-5", Delta: 1 << 53, ActorID: "admin-4", Reason: "unsafe"},
	} {
		if err := value.Validate(); !errors.Is(err, ErrDenied) {
			t.Fatalf("value=%+v err=%v", value, err)
		}
	}
}

func TestAdminAdjustmentRejectsUnknownResultField(t *testing.T) {
	var result AdminAdjustment
	if err := json.Unmarshal([]byte(`{"state":"unknown","operation_id":"op-6","organization_id":"org-2","user_id":"user-3","delta":1,"actor_id":"admin-4","reason":"recover","before_quota":7}`), &result); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err=%v", err)
	}
}

func TestAdminAdjustEnforcesHTTPStatusStateMatrix(t *testing.T) {
	requestValue := AdminAdjustRequest{OrganizationID: "org-2", UserID: "user-3", OperationID: "op-matrix", Delta: 10, ActorID: "admin-4", Reason: "matrix"}
	for _, tc := range []struct {
		name    string
		status  int
		state   AdminAdjustmentState
		success bool
	}{
		{"200 applied", http.StatusOK, AdminAdjustmentApplied, true},
		{"200 dispatching", http.StatusOK, AdminAdjustmentDispatching, false},
		{"200 unknown", http.StatusOK, AdminAdjustmentUnknown, false},
		{"200 rejected", http.StatusOK, AdminAdjustmentRejected, false},
		{"202 dispatching", http.StatusAccepted, AdminAdjustmentDispatching, true},
		{"202 unknown", http.StatusAccepted, AdminAdjustmentUnknown, true},
		{"202 applied", http.StatusAccepted, AdminAdjustmentApplied, false},
		{"202 rejected", http.StatusAccepted, AdminAdjustmentRejected, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			responseValue := AdminAdjustment{State: tc.state, OperationID: requestValue.OperationID, OrganizationID: requestValue.OrganizationID, UserID: requestValue.UserID, Delta: requestValue.Delta, ActorID: requestValue.ActorID, Reason: requestValue.Reason}
			body, err := json.Marshal(responseValue)
			if err != nil {
				t.Fatal(err)
			}
			client, err := NewClientWithTransport(Config{Endpoint: "https://credits.example"}, adjustRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.AdminAdjust(context.Background(), requestValue)
			if tc.success && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.success && !errors.Is(err, ErrUnavailable) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestGetAdminAdjustmentAcceptsFourStatesOnlyOnOK(t *testing.T) {
	lookup := AdminAdjustLookup{OrganizationID: "org-2", UserID: "user-3", OperationID: "op-result"}
	for _, state := range []AdminAdjustmentState{AdminAdjustmentDispatching, AdminAdjustmentApplied, AdminAdjustmentRejected, AdminAdjustmentUnknown} {
		t.Run(string(state), func(t *testing.T) {
			responseValue := AdminAdjustment{State: state, OperationID: lookup.OperationID, OrganizationID: lookup.OrganizationID, UserID: lookup.UserID, Delta: 1, ActorID: "admin-4", Reason: "read result"}
			body, err := json.Marshal(responseValue)
			if err != nil {
				t.Fatal(err)
			}
			for _, status := range []int{http.StatusOK, http.StatusAccepted} {
				client, err := NewClientWithTransport(Config{Endpoint: "https://credits.example"}, adjustRoundTripFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				result, callErr := client.GetAdminAdjustment(context.Background(), lookup)
				if status == http.StatusOK && (callErr != nil || result.State != state) {
					t.Fatalf("state=%s status=%d result=%+v err=%v", state, status, result, callErr)
				}
				if status != http.StatusOK && !errors.Is(callErr, ErrUnavailable) {
					t.Fatalf("state=%s status=%d err=%v", state, status, callErr)
				}
			}
		})
	}
}

type closeErrorBody struct{ io.Reader }

func (closeErrorBody) Close() error { return errors.New("synthetic close failure") }

func TestAdminAdjustAppliedSurvivesBodyCloseFailureWithoutRetry(t *testing.T) {
	requestValue := AdminAdjustRequest{OrganizationID: "org-2", UserID: "user-3", OperationID: "op-close", Delta: 10, ActorID: "admin-4", Reason: "close cleanup"}
	responseValue := AdminAdjustment{State: AdminAdjustmentApplied, OperationID: requestValue.OperationID, OrganizationID: requestValue.OrganizationID, UserID: requestValue.UserID, Delta: requestValue.Delta, ActorID: requestValue.ActorID, Reason: requestValue.Reason}
	body, err := json.Marshal(responseValue)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	client, err := NewClientWithTransport(Config{Endpoint: "https://credits.example"}, adjustRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: closeErrorBody{Reader: strings.NewReader(string(body))}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.AdminAdjust(context.Background(), requestValue)
	if err != nil || result.State != AdminAdjustmentApplied || calls != 1 {
		t.Fatalf("result=%+v err=%v calls=%d", result, err, calls)
	}
}

func TestLegacyCreditsClientErrorContractIsPreserved(t *testing.T) {
	subject := Subject{OrganizationID: "org-2", UserID: "user-3"}
	for _, tc := range []struct {
		status int
		want   error
	}{{http.StatusConflict, ErrDenied}, {http.StatusNotFound, ErrUnavailable}} {
		client, err := NewClientWithTransport(Config{Endpoint: "https://credits.example"}, adjustRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = client.AcquireDefault(context.Background(), subject); !errors.Is(err, tc.want) {
			t.Fatalf("status=%d err=%v", tc.status, err)
		}
	}
}
