package server

import (
	"errors"
	"testing"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
)

func TestAuthInjectorPublishesIdentityAfterSuccess(t *testing.T) {
	ctx, _ := gin.CreateTestContext(nil)
	ls := &auth.LoginStatus{
		State: auth.StateSucc,
		Claim: &auth.UserClaims{UserID: 42, UIN: 84, CompanyID: 126, MembershipEpoch: 7},
	}
	ctx.Set(constants.CtxKeyLoginStatus, ls)

	ai := &authInjector{injector: func(_ *gin.Context, got *auth.LoginStatus) error {
		if got != ls {
			t.Fatal("injector received a different LoginStatus")
		}
		ctx.Set(constants.CtxKeyMembershipEpoch, got.Claim.MembershipEpoch)
		return nil
	}}
	ai.Inject(ctx)

	if got := ctx.GetUint(constants.CtxKeyUserID); got != 42 {
		t.Fatalf("UserID = %d, want 42", got)
	}
	if got := ctx.GetUint(constants.CtxKeyUIN); got != 84 {
		t.Fatalf("UIN = %d, want 84", got)
	}
	if got := ctx.GetUint(constants.CtxKeyCompanyID); got != 126 {
		t.Fatalf("CompanyID = %d, want 126", got)
	}
	if got := ctx.GetUint64(constants.CtxKeyMembershipEpoch); got != 7 {
		t.Fatalf("MembershipEpoch = %d, want 7", got)
	}
	if ls.State != auth.StateSucc {
		t.Fatalf("State = %d, want StateSucc", ls.State)
	}
}

func TestAuthInjectorDoesNotPublishUserIDAfterFailure(t *testing.T) {
	ctx, _ := gin.CreateTestContext(nil)
	ctx.Set(constants.CtxKeyUserID, uint(99))
	ctx.Set(constants.CtxKeyUIN, uint(98))
	ctx.Set(constants.CtxKeyCompanyID, uint(97))
	ctx.Set(constants.CtxKeyMembershipEpoch, uint64(96))
	ls := &auth.LoginStatus{
		State: auth.StateSucc,
		Claim: &auth.UserClaims{UserID: 42, UIN: 84, CompanyID: 126},
	}
	ctx.Set(constants.CtxKeyLoginStatus, ls)
	wantErr := errors.New("user lookup failed")

	ai := &authInjector{injector: func(_ *gin.Context, _ *auth.LoginStatus) error {
		return wantErr
	}}
	ai.Inject(ctx)

	if got := ctx.GetUint(constants.CtxKeyUserID); got != 0 {
		t.Fatalf("UserID = %d, want 0", got)
	}
	if got := ctx.GetUint(constants.CtxKeyUIN); got != 0 {
		t.Fatalf("UIN = %d, want 0", got)
	}
	if got := ctx.GetUint(constants.CtxKeyCompanyID); got != 0 {
		t.Fatalf("CompanyID = %d, want 0", got)
	}
	if got := ctx.GetUint64(constants.CtxKeyMembershipEpoch); got != 0 {
		t.Fatalf("MembershipEpoch = %d, want 0", got)
	}
	if ls.State != auth.StateFailed {
		t.Fatalf("State = %d, want StateFailed", ls.State)
	}
	if !errors.Is(ls.Err, wantErr) {
		t.Fatalf("LoginStatus error = %v, want %v", ls.Err, wantErr)
	}
}

func TestAuthInjectorFailsWhenNotConfigured(t *testing.T) {
	ctx, _ := gin.CreateTestContext(nil)
	ls := &auth.LoginStatus{
		State: auth.StateSucc,
		Claim: &auth.UserClaims{UserID: 42, UIN: 84, CompanyID: 126},
	}
	ctx.Set(constants.CtxKeyLoginStatus, ls)

	new(authInjector).Inject(ctx)

	if ls.State != auth.StateFailed {
		t.Fatalf("State = %d, want StateFailed", ls.State)
	}
	if !errors.Is(ls.Err, auth.ErrAuthBackendUnavailable) {
		t.Fatalf("LoginStatus error = %v, want ErrAuthBackendUnavailable", ls.Err)
	}
}
