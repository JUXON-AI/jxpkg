package middleware

import (
	"context"
	"encoding/json"
	"io"
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

func TestCreditsBindingUsesVerifiedBrowserSubjectAndStaysLazy(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		valid, expired, acquire bool
		status, calls           int
	}{
		{"valid", true, false, true, 204, 1},
		{"metadata_only", true, false, false, 204, 0},
		{"missing_browser", false, false, true, 401, 0},
		{"expired", true, true, true, 401, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client, err := credits.NewClientWithTransport(credits.Config{Endpoint: "https://credits.example.com"}, creditsTransportFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				var subject credits.Subject
				if json.NewDecoder(r.Body).Decode(&subject) != nil || subject != (credits.Subject{CompanyID: 2, UIN: 3}) {
					t.Error("request overrode verified employee")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"base_url":"https://models.example.com/v1","api_key":"employee-default"}`))}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			engine := gin.New()
			engine.POST("/model", func(ctx *gin.Context) {
				if tc.valid {
					expires := time.Now().Add(time.Hour).Unix()
					if tc.expired {
						expires = time.Now().Add(-time.Hour).Unix()
					}
					ctx.Set(constants.CtxKeyUserID, uint(1))
					ctx.Set(constants.CtxKeyCompanyID, uint(2))
					ctx.Set(constants.CtxKeyUIN, uint(3))
					ctx.Set(constants.CtxKeyMembershipEpoch, uint64(1))
					ctx.Set(constants.CtxKeyLoginStatus, auth.NewBrowserSessionLoginStatus(auth.SessionPrincipal{Claims: auth.UserClaims{UserID: 1, CompanyID: 2, UIN: 3, MembershipEpoch: 1}, IdleExpiresAt: expires, AbsoluteExpiresAt: expires}))
				}
				ctx.Next()
			}, BindCreditsExecution(client), func(ctx *gin.Context) {
				a, err := credits.ExecutionFromContext(ctx)
				if err != nil {
					t.Fatal(err)
				}
				b, err := credits.ExecutionFromContext(ctx.Request.Context())
				if err != nil || a != b {
					t.Fatal("Gin and standard Context have different executions")
				}
				if tc.acquire {
					for i := 0; i < 2; i++ {
						if _, err := credits.ConnectionFromContext(context.WithValue(ctx, "trace", "request")); err != nil {
							t.Error(err)
						}
					}
				}
				ctx.Status(204)
			})
			request := httptest.NewRequest("POST", "/model", strings.NewReader(`{"company_id":99,"uin":99}`))
			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, request)
			if recorder.Code != tc.status || calls != tc.calls {
				t.Fatalf("status=%d calls=%d", recorder.Code, calls)
			}
		})
	}
}
