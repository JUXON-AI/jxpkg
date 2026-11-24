package credits

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/JUXON-AI/jxpkg/requestid"
)

func TestUsageSummaryProtocolRejectsIncompleteMalformedOrCredentialResponses(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       error
	}{
		{"valid", `{"state":"ready","monthly_remaining_percent":73.25,"next_reset_at":1767225600,"subscription_ends_at":1798761600,"points_balance":"745.90"}`, http.StatusOK, nil},
		{"nullable", `{"state":"uninitialized","monthly_remaining_percent":null,"next_reset_at":null,"subscription_ends_at":null,"points_balance":null}`, http.StatusOK, nil},
		{"pending_partial", `{"state":"pending","monthly_remaining_percent":42.5,"next_reset_at":null,"subscription_ends_at":1798761600,"points_balance":null}`, http.StatusOK, nil},
		{"missing_field", `{"state":"ready","monthly_remaining_percent":null,"next_reset_at":null,"subscription_ends_at":null}`, http.StatusOK, ErrUnavailable},
		{"duplicate", `{"state":"ready","state":"pending","monthly_remaining_percent":null,"next_reset_at":null,"subscription_ends_at":null,"points_balance":null}`, http.StatusOK, ErrUnavailable},
		{"case_alias", `{"State":"ready","monthly_remaining_percent":null,"next_reset_at":null,"subscription_ends_at":null,"points_balance":null}`, http.StatusOK, ErrUnavailable},
		{"legacy_quota", `{"state":"ready","quota":6500,"used_quota":3500,"monthly_remaining_percent":null,"next_reset_at":null,"subscription_ends_at":null,"points_balance":null}`, http.StatusOK, ErrUnavailable},
		{"state_null", `{"state":null,"monthly_remaining_percent":null,"next_reset_at":null,"subscription_ends_at":null,"points_balance":null}`, http.StatusOK, ErrUnavailable},
		{"bad_state", `{"state":"repair_required","monthly_remaining_percent":null,"next_reset_at":null,"subscription_ends_at":null,"points_balance":null}`, http.StatusOK, ErrUnavailable},
		{"percent_low", `{"state":"ready","monthly_remaining_percent":-0.01,"next_reset_at":null,"subscription_ends_at":null,"points_balance":null}`, http.StatusOK, ErrUnavailable},
		{"percent_high", `{"state":"ready","monthly_remaining_percent":100.01,"next_reset_at":null,"subscription_ends_at":null,"points_balance":null}`, http.StatusOK, ErrUnavailable},
		{"percent_type", `{"state":"ready","monthly_remaining_percent":"50","next_reset_at":null,"subscription_ends_at":null,"points_balance":null}`, http.StatusOK, ErrUnavailable},
		{"reset_zero", `{"state":"ready","monthly_remaining_percent":null,"next_reset_at":0,"subscription_ends_at":null,"points_balance":null}`, http.StatusOK, ErrUnavailable},
		{"reset_fraction", `{"state":"ready","monthly_remaining_percent":null,"next_reset_at":1.5,"subscription_ends_at":null,"points_balance":null}`, http.StatusOK, ErrUnavailable},
		{"subscription_nonpositive", `{"state":"ready","monthly_remaining_percent":null,"next_reset_at":null,"subscription_ends_at":-1,"points_balance":null}`, http.StatusOK, ErrUnavailable},
		{"subscription_unsafe", `{"state":"ready","monthly_remaining_percent":null,"next_reset_at":null,"subscription_ends_at":1000000000001,"points_balance":null}`, http.StatusOK, ErrUnavailable},
		{"points_format", `{"state":"ready","monthly_remaining_percent":null,"next_reset_at":null,"subscription_ends_at":null,"points_balance":"1e5"}`, http.StatusOK, ErrUnavailable},
		{"points_type", `{"state":"ready","monthly_remaining_percent":null,"next_reset_at":null,"subscription_ends_at":null,"points_balance":1}`, http.StatusOK, ErrUnavailable},
		{"credential", `{"state":"ready","monthly_remaining_percent":null,"next_reset_at":null,"subscription_ends_at":null,"points_balance":null,"api_key":"secret"}`, http.StatusOK, ErrUnavailable},
		{"trailing", `{"state":"ready","monthly_remaining_percent":null,"next_reset_at":null,"subscription_ends_at":null,"points_balance":null}{}`, http.StatusOK, ErrUnavailable},
		{"denied", `secret`, http.StatusForbidden, ErrDenied},
		{"failure", `secret`, http.StatusServiceUnavailable, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client, err := NewClientWithTransport(Config{Endpoint: "https://credits.example.com"}, transportFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.Path != BalancePath || request.Header.Get("X-Request-Id") != "summary-request" || request.Header.Get("X-JX-Credits-Points") != "1" {
					t.Error("wrong summary path, request ID, or points negotiation")
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			summary, err := client.GetUsageSummary(requestid.WithContext(context.Background(), "summary-request"), Subject{OrganizationID: "org-2", UserID: "user-3"})
			if !errors.Is(err, tc.want) || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
			if err != nil && summary != (UsageSummary{}) {
				t.Fatal("failed query returned a summary")
			}
		})
	}
}

func TestUsageSummaryPreservesNullableDisplayValues(t *testing.T) {
	client, err := NewClientWithTransport(Config{Endpoint: "https://credits.example.com"}, transportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"state":"ready","monthly_remaining_percent":73.25,"next_reset_at":1767225600,"subscription_ends_at":1798761600,"points_balance":">-0.01"}`))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	summary, err := client.GetUsageSummary(context.Background(), Subject{OrganizationID: "org-2", UserID: "user-3"})
	percent := 73.25
	nextReset := int64(1767225600)
	subscriptionEnds := int64(1798761600)
	points := ">-0.01"
	want := UsageSummary{State: "ready", MonthlyRemainingPercent: &percent, NextResetAt: &nextReset, SubscriptionEndsAt: &subscriptionEnds, PointsBalance: &points}
	if err != nil || !reflect.DeepEqual(summary, want) {
		t.Fatalf("summary=%+v err=%v, want %+v", summary, err, want)
	}
}

func TestValidateUsageSummaryBoundaries(t *testing.T) {
	zero := 0.0
	maxPercent := 100.0
	one := int64(1)
	zeroPoints := "0"
	if err := ValidateUsageSummary(UsageSummary{State: "ready", MonthlyRemainingPercent: &zero, NextResetAt: &one, SubscriptionEndsAt: &one, PointsBalance: &zeroPoints}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateUsageSummary(UsageSummary{State: "pending", MonthlyRemainingPercent: &maxPercent}); err != nil {
		t.Fatal(err)
	}
	invalidPercent := 100.01
	nanPercent := math.NaN()
	invalidTime := int64(0)
	unsafeTime := int64(1_000_000_000_001)
	invalidPoints := "1.1234567890123"
	for _, summary := range []UsageSummary{
		{State: ""},
		{State: "ready", MonthlyRemainingPercent: &invalidPercent},
		{State: "ready", MonthlyRemainingPercent: &nanPercent},
		{State: "ready", NextResetAt: &invalidTime},
		{State: "ready", SubscriptionEndsAt: &unsafeTime},
		{State: "ready", PointsBalance: &invalidPoints},
	} {
		if !errors.Is(ValidateUsageSummary(summary), ErrUnavailable) {
			t.Fatalf("summary passed validation: %+v", summary)
		}
	}
}
