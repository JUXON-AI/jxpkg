package credits

import (
	"context"
	"errors"
	"github.com/JUXON-AI/jxpkg/requestid"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestBalanceProtocolRejectsIncompleteOrCredentialResponses(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       error
	}{
		{"valid", `{"state":"ready","quota":6500,"used_quota":3500}`, 200, nil},
		{"zero", `{"state":"ready","quota":0,"used_quota":0}`, 200, nil},
		{"settlement_debt", `{"state":"ready","quota":-10,"used_quota":100}`, 200, nil},
		{"missing_used", `{"state":"ready","quota":6500}`, 200, ErrUnavailable},
		{"duplicate", `{"state":"ready","quota":6500,"quota":0,"used_quota":3500}`, 200, ErrUnavailable},
		{"case_alias", `{"state":"ready","quota":6500,"Quota":0,"used_quota":3500}`, 200, ErrUnavailable},
		{"null", `{"state":"ready","quota":null,"used_quota":0}`, 200, ErrUnavailable},
		{"bad_state", `{"state":"repair_required","quota":0,"used_quota":0}`, 200, ErrUnavailable},
		{"negative_used", `{"state":"ready","quota":1,"used_quota":-1}`, 200, ErrUnavailable},
		{"unsafe_integer", `{"state":"ready","quota":9007199254740992,"used_quota":0}`, 200, ErrUnavailable},
		{"credential", `{"state":"ready","quota":1,"used_quota":0,"api_key":"secret"}`, 200, ErrUnavailable},
		{"points_null", `{"state":"ready","quota":1,"used_quota":0,"points":null}`, 200, ErrUnavailable},
		{"points_missing_ratio", `{"state":"ready","quota":1,"used_quota":0,"points":{"balance":"<0.01","used":"0.00","unit":"分"}}`, 200, ErrUnavailable},
		{"points_duplicate", `{"state":"ready","quota":1,"used_quota":0,"points":{"balance":"<0.01","used":"0.00","used":"1.00","quota_per_point":5000,"unit":"分"}}`, 200, ErrUnavailable},
		{"points_case_alias", `{"state":"ready","quota":1,"used_quota":0,"points":{"Balance":"<0.01","used":"0.00","quota_per_point":5000,"unit":"分"}}`, 200, ErrUnavailable},
		{"points_negative_used", `{"state":"ready","quota":1,"used_quota":0,"points":{"balance":"<0.01","used":"-1.00","quota_per_point":5000,"unit":"分"}}`, 200, ErrUnavailable},
		{"points_while_pending", `{"state":"pending","quota":0,"used_quota":0,"points":{"balance":"0.00","used":"0.00","quota_per_point":5000,"unit":"分"}}`, 200, ErrUnavailable},
		{"trailing", `{"state":"ready","quota":1,"used_quota":0}{}`, 200, ErrUnavailable},
		{"denied", `secret`, 403, ErrDenied},
		{"failure", `secret`, 503, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c, err := NewClientWithTransport(Config{Endpoint: "https://credits.example.com"}, transportFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Path != BalancePath || r.Header.Get("X-Request-Id") != "balance-request" || r.Header.Get("X-JX-Credits-Points") != "1" {
					t.Error("wrong balance path, request ID, or points negotiation")
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			b, err := c.GetBalance(requestid.WithContext(context.Background(), "balance-request"), Subject{OrganizationID: "org-2", UserID: "user-3"})
			if !errors.Is(err, tc.want) || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
			if err != nil && b != (Balance{}) {
				t.Fatal("failed query returned a snapshot")
			}
			if err == nil && b.Points != nil {
				t.Fatal("legacy raw balance acquired fabricated points")
			}
		})
	}
}

func TestBalancePreservesCreditsPointsAndRawValues(t *testing.T) {
	client, err := NewClientWithTransport(Config{Endpoint: "https://credits.example.com"}, transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-JX-Credits-Points") != "1" {
			t.Error("missing points opt-in")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"state":"ready","quota":-1,"used_quota":700,"points":{"balance":">-0.01","used":"2.00","quota_per_point":350,"unit":"分"}}`))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := client.GetBalance(context.Background(), Subject{OrganizationID: "org-2", UserID: "user-3"})
	if err != nil || b.Quota != -1 || b.UsedQuota != 700 || b.Points == nil || *b.Points != (BalancePoints{Balance: ">-0.01", Used: "2.00", QuotaPerPoint: 350, Unit: "分"}) {
		t.Fatalf("provider points or raw values were lost: %+v, err=%v", b, err)
	}
}
