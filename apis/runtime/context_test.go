package runtime

import (
	"testing"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
)

func TestBrowserSessionExpiresAt(t *testing.T) {
	tests := []struct {
		name   string
		status *auth.LoginStatus
		want   int64
	}{
		{
			name: "idle expiry is earlier",
			status: auth.NewBrowserSessionLoginStatus(auth.SessionPrincipal{
				Claims:        auth.UserClaims{UserID: 1, UIN: 2, CompanyID: 3, MembershipEpoch: 4},
				IdleExpiresAt: 200, AbsoluteExpiresAt: 300,
			}),
			want: 200,
		},
		{
			name: "absolute expiry is earlier",
			status: auth.NewBrowserSessionLoginStatus(auth.SessionPrincipal{
				Claims:        auth.UserClaims{UserID: 1, UIN: 2, CompanyID: 3, MembershipEpoch: 4},
				IdleExpiresAt: 400, AbsoluteExpiresAt: 300,
			}),
			want: 300,
		},
		{
			name: "bearer is not a browser session",
			status: &auth.LoginStatus{
				AuthMode: auth.AuthModeBearer,
				Claim:    &auth.UserClaims{ExpiresAt: 123},
			},
		},
		{
			name: "missing metadata fails closed",
			status: &auth.LoginStatus{
				AuthMode: auth.AuthModeBrowserSession,
				Claim:    &auth.UserClaims{UserID: 1, UIN: 2, CompanyID: 3, MembershipEpoch: 4},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, _ := gin.CreateTestContext(nil)
			ctx.Set(constants.CtxKeyLoginStatus, test.status)
			if got := BrowserSessionExpiresAt(ctx); got != test.want {
				t.Fatalf("BrowserSessionExpiresAt() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestLoginWay(t *testing.T) {
	ctx, _ := gin.CreateTestContext(nil)
	if got := LoginWay(ctx); got != auth.LoginWayUnknown {
		t.Fatalf("LoginWay() = %d, want unknown", got)
	}
	ctx.Set(constants.CtxKeyLoginStatus, &auth.LoginStatus{
		State: auth.StateSucc,
		Claim: &auth.UserClaims{LoginWay: auth.LoginWayEmail},
	})
	if got := LoginWay(ctx); got != auth.LoginWayEmail {
		t.Fatalf("LoginWay() = %d, want email", got)
	}
}
