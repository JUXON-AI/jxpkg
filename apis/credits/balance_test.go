package credits

import (
	"context"
	"encoding/json"
	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/JUXON-AI/jxpkg/apis/runtime/server"
	clientcredits "github.com/JUXON-AI/jxpkg/credits"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type balanceTransport func(*http.Request) (*http.Response, error)

func (f balanceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBrowserBalanceUsesSessionAndNeverRequestIdentity(t *testing.T) {
	for _, tc := range []struct {
		name         string
		valid        bool
		remoteStatus int
		want         uint32
		calls        int
	}{
		{"valid", true, 200, 0, 1}, {"missing_session", false, 200, 403, 0}, {"denied", true, 403, 403, 1}, {"dependency", true, 503, 503, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client, err := clientcredits.NewClientWithTransport(clientcredits.Config{Endpoint: "https://credits.example.com"}, balanceTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				var subject clientcredits.Subject
				if json.NewDecoder(r.Body).Decode(&subject) != nil || subject != (clientcredits.Subject{CompanyID: 2, UIN: 3}) || r.URL.Path != clientcredits.BalancePath {
					t.Error("unverified identity or credential acquisition")
				}
				return &http.Response{StatusCode: tc.remoteStatus, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"state":"ready","quota":6500,"used_quota":3500}`))}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			ctx.Request = httptest.NewRequest("POST", "/v1/jxagent.GetMyModelBalance", strings.NewReader(`{"request":{"uin":99,"company_id":99}}`))
			if tc.valid {
				ctx.Set(constants.CtxKeyUserID, uint(1))
				ctx.Set(constants.CtxKeyCompanyID, uint(2))
				ctx.Set(constants.CtxKeyUIN, uint(3))
				ctx.Set(constants.CtxKeyMembershipEpoch, uint64(1))
				expires := time.Now().Add(time.Hour).Unix()
				ctx.Set(constants.CtxKeyLoginStatus, auth.NewBrowserSessionLoginStatus(auth.SessionPrincipal{Claims: auth.UserClaims{UserID: 1, UIN: 3, CompanyID: 2, MembershipEpoch: 1}, IdleExpiresAt: expires, AbsoluteExpiresAt: expires}))
			}
			var resp GetMyModelBalanceResponse
			balanceHandler(client)(ctx, &GetMyModelBalanceRequest{}, &resp)
			if resp.Code != tc.want || calls != tc.calls || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("code=%d calls=%d", resp.Code, calls)
			}
			if resp.Code != 0 && resp.Response != (BrowserBalance{}) {
				t.Fatal("failure presented as a balance")
			}
			if resp.Code == 0 && (resp.Response.CompanyID != 2 || resp.Response.UIN != 3) {
				t.Fatal("response did not echo verified employee")
			}
		})
	}
}

func TestRegistrationKeepsAuthenticationFailClosed(t *testing.T) {
	calls := 0
	client, err := clientcredits.NewClientWithTransport(clientcredits.Config{Endpoint: "https://credits.example.com"}, balanceTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, context.DeadlineExceeded }))
	if err != nil {
		t.Fatal(err)
	}
	router := server.NewRouter("/v1/")
	if err := RegisterBrowserBalance(router, "jxagent", client); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	router.GinEngine().ServeHTTP(w, httptest.NewRequest("POST", "/v1/jxagent.GetMyModelBalance", strings.NewReader(`{"request":{}}`)))
	if w.Code != 503 || calls != 0 {
		t.Fatalf("unconfigured auth status=%d calls=%d", w.Code, calls)
	}
	if RegisterBrowserBalance(router, "../other", client) == nil || RegisterBrowserBalance(router, "jxagent", nil) == nil {
		t.Fatal("invalid registration accepted")
	}
}
