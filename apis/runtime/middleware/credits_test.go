package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/JUXON-AI/jxpkg/credits"
	"github.com/gin-gonic/gin"
)

type creditsTransportFunc func(*http.Request) (*http.Response, error)

func (f creditsTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCreditsBindingRejectsLegacyAndRequestIdentity(t *testing.T) {
	calls := 0
	client, err := credits.NewClientWithTransport(credits.Config{Endpoint: "https://credits.example.com"}, creditsTransportFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, context.DeadlineExceeded }))
	if err != nil {
		t.Fatal(err)
	}
	engine := gin.New()
	engine.POST("/model", func(ctx *gin.Context) {
		expires := time.Now().Add(time.Hour).Unix()
		ctx.Set(constants.CtxKeyUserID, uint(1))
		ctx.Set(constants.CtxKeyCompanyID, uint(2))
		ctx.Set(constants.CtxKeyUIN, uint(3))
		ctx.Set(constants.CtxKeyMembershipEpoch, uint64(1))
		ctx.Set(constants.CtxKeyLoginStatus, auth.NewBrowserSessionLoginStatus(auth.SessionPrincipal{Claims: auth.UserClaims{UserID: 1, CompanyID: 2, UIN: 3, MembershipEpoch: 1}, IdleExpiresAt: expires, AbsoluteExpiresAt: expires}))
	}, BindCreditsExecution(client), func(ctx *gin.Context) { t.Error("legacy identity reached protected model execution"); ctx.Status(204) })
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/model", strings.NewReader(`{"organization_id":"forged","user_id":"forged"}`))
	r.Header.Set("X-Organization-ID", "forged")
	engine.ServeHTTP(w, r)
	if w.Code != 401 || calls != 0 {
		t.Fatal("legacy or request identity reached credits")
	}
}
