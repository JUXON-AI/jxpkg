package server

import (
	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
)

type authInjector struct {
	injector auth.InjectorFunc
}

// AuthInject 注册认证通过后的用户校验函数。
func (ai *authInjector) AuthInject(injector auth.InjectorFunc) {
	ai.injector = injector
}

// Inject 校验业务用户，并在成功后发布用户 ID。
func (ai *authInjector) Inject(ctx *gin.Context) {
	val, ok := ctx.Get(constants.CtxKeyLoginStatus)
	if !ok {
		ctx.Next()
		return
	}
	ls, ok := val.(*auth.LoginStatus)
	if !ok || ls == nil || ls.State != auth.StateSucc {
		ctx.Next()
		return
	}

	clearPrincipal(ctx)
	if ls.Claim == nil || ls.Claim.UserID == 0 || ls.Claim.UIN == 0 || ls.Claim.CompanyID == 0 ||
		ls.AuthMode != auth.AuthModeBearer {
		rejectPrincipal(ctx, ls, auth.ErrInvalidPrincipal)
		ctx.Next()
		return
	}
	if ai.injector == nil {
		rejectPrincipal(ctx, ls, auth.ErrAuthBackendUnavailable)
		ctx.Next()
		return
	}
	err := ai.injector(ctx, ls)
	if err == nil && (ls.State != auth.StateSucc || ls.Claim == nil || ls.Claim.UserID == 0 || ls.Claim.UIN == 0 || ls.Claim.CompanyID == 0) {
		err = auth.ErrInvalidPrincipal
	}
		if err != nil {
		rejectPrincipal(ctx, ls, err)
		ctx.Next()
		return
	}

	publishPrincipal(ctx, ls.Claim)
	ctx.Next()
}

// publishBrowserPrincipal publishes only the principal already verified by the
// browser Session resolver. Bearer AuthInject callbacks never run on this path.
func (*authInjector) publishBrowserPrincipal(ctx *gin.Context) {
	val, ok := ctx.Get(constants.CtxKeyLoginStatus)
	if !ok {
		ctx.Next()
		return
	}
	ls, ok := val.(*auth.LoginStatus)
	if !ok || ls == nil || ls.State != auth.StateSucc {
		ctx.Next()
		return
	}

	clearPrincipal(ctx)
	if ls.AuthMode != auth.AuthModeBrowserSession || ls.Claim == nil || ls.Claim.UserID == 0 || ls.Claim.UIN == 0 ||
		ls.Claim.CompanyID == 0 || ls.Claim.MembershipEpoch == 0 {
		rejectPrincipal(ctx, ls, auth.ErrInvalidPrincipal)
		ctx.Next()
		return
	}

	publishPrincipal(ctx, ls.Claim)
	ctx.Set(constants.CtxKeyMembershipEpoch, ls.Claim.MembershipEpoch)
	ctx.Next()
}

func clearPrincipal(ctx *gin.Context) {
	ctx.Set(constants.CtxKeyUserID, uint(0))
	ctx.Set(constants.CtxKeyUIN, uint(0))
	ctx.Set(constants.CtxKeyCompanyID, uint(0))
	ctx.Set(constants.CtxKeyMembershipEpoch, uint64(0))
}

func rejectPrincipal(ctx *gin.Context, ls *auth.LoginStatus, err error) {
	clearPrincipal(ctx)
	ls.State = auth.StateFailed
	ls.Err = err
	ctx.Set(constants.CtxKeyLoginStatus, ls)
}

func publishPrincipal(ctx *gin.Context, claims *auth.UserClaims) {
	ctx.Set(constants.CtxKeyUserID, claims.UserID)
	ctx.Set(constants.CtxKeyUIN, claims.UIN)
	ctx.Set(constants.CtxKeyCompanyID, claims.CompanyID)
}
