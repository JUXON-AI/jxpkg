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
		{"trailing", `{"state":"ready","quota":1,"used_quota":0}{}`, 200, ErrUnavailable},
		{"denied", `secret`, 403, ErrDenied},
		{"failure", `secret`, 503, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c, err := NewClientWithTransport(Config{Endpoint: "https://credits.example.com"}, transportFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Path != BalancePath || r.Header.Get("X-Request-Id") != "balance-request" {
					t.Error("wrong balance path or lost request ID")
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			b, err := c.GetBalance(requestid.WithContext(context.Background(), "balance-request"), Subject{CompanyID: 2, UIN: 3})
			if !errors.Is(err, tc.want) || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
			if err != nil && b != (Balance{}) {
				t.Fatal("failed query returned a snapshot")
			}
		})
	}
}
