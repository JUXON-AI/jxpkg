package credits

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/JUXON-AI/jxpkg/apis/runtime/server"
	clientcredits "github.com/JUXON-AI/jxpkg/credits"
	"github.com/gin-gonic/gin"
)

type balanceTransport func(*http.Request) (*http.Response, error)

func (f balanceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBrowserBalanceRejectsLegacyAndRequestIdentity(t *testing.T) {
	calls := 0
	client, err := clientcredits.NewClientWithTransport(clientcredits.Config{Endpoint: "https://credits.example.com"}, balanceTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, context.DeadlineExceeded }))
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("POST", "/v1/jxagent.GetMyModelBalance", strings.NewReader(`{"request":{"organization_id":"forged","user_id":"forged","uin":99,"company_id":99}}`))
	expires := time.Now().Add(time.Hour).Unix()
	ctx.Set(constants.CtxKeyUserID, uint(1))
	ctx.Set(constants.CtxKeyCompanyID, uint(2))
	ctx.Set(constants.CtxKeyUIN, uint(3))
	ctx.Set(constants.CtxKeyMembershipEpoch, uint64(1))
	ctx.Set(constants.CtxKeyLoginStatus, auth.NewBrowserSessionLoginStatus(auth.SessionPrincipal{Claims: auth.UserClaims{UserID: 1, CompanyID: 2, UIN: 3, MembershipEpoch: 1}, IdleExpiresAt: expires, AbsoluteExpiresAt: expires}))
	var resp GetMyModelBalanceResponse
	balanceHandler(client)(ctx, &GetMyModelBalanceRequest{}, &resp)
	if resp.Code != 403 || calls != 0 || resp.Response != (BrowserBalance{}) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("legacy or request identity reached credits")
	}
}

func TestRegistrationRequiresLogtoRuntime(t *testing.T) {
	router := server.NewRouter("/v1/")
	client, err := clientcredits.NewClientWithTransport(clientcredits.Config{Endpoint: "https://credits.example.com"}, balanceTransport(func(*http.Request) (*http.Response, error) {
		t.Error("unexpected remote request")
		return nil, context.DeadlineExceeded
	}))
	if err != nil {
		t.Fatal(err)
	}
	if RegisterBrowserBalance(router, "jxagent", client, nil) == nil || len(router.GinEngine().Routes()) != 0 {
		t.Fatal("unconfigured Logto authentication registered a route")
	}
}
