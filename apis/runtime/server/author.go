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
	ai.inject(ctx, false)
}

// publishBrowserPrincipal accepts an already resolved browser principal without
// requiring application glue. Explicit callbacks still run and may reject it.
func (ai *authInjector) publishBrowserPrincipal(ctx *gin.Context) {
	ai.inject(ctx, true)
}

func (ai *authInjector) inject(ctx *gin.Context, browser bool) {
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

	ctx.Set(constants.CtxKeyUserID, uint(0))
	ctx.Set(constants.CtxKeyUIN, uint(0))
	ctx.Set(constants.CtxKeyCompanyID, uint(0))
	ctx.Set(constants.CtxKeyMembershipEpoch, uint64(0))
	if ls.Claim == nil || ls.Claim.UserID == 0 || ls.Claim.UIN == 0 || ls.Claim.CompanyID == 0 ||
		(browser && (ls.AuthMode != auth.AuthModeBrowserSession || ls.Claim.MembershipEpoch == 0)) {
		ls.State = auth.StateFailed
		ls.Err = auth.ErrInvalidPrincipal
		ctx.Set(constants.CtxKeyLoginStatus, ls)
		ctx.Next()
		return
	}
	if ai.injector == nil && !browser {
		ls.State = auth.StateFailed
		ls.Err = auth.ErrAuthBackendUnavailable
		ctx.Set(constants.CtxKeyLoginStatus, ls)
		ctx.Next()
		return
	}
	if ai.injector != nil {
		err := ai.injector(ctx, ls)
		if err == nil && (ls.State != auth.StateSucc || ls.Claim == nil || ls.Claim.UserID == 0 || ls.Claim.UIN == 0 || ls.Claim.CompanyID == 0 ||
			(browser && (ls.AuthMode != auth.AuthModeBrowserSession || ls.Claim.MembershipEpoch == 0))) {
			err = auth.ErrInvalidPrincipal
		}
		if err != nil {
			ctx.Set(constants.CtxKeyUserID, uint(0))
			ctx.Set(constants.CtxKeyUIN, uint(0))
			ctx.Set(constants.CtxKeyCompanyID, uint(0))
			ctx.Set(constants.CtxKeyMembershipEpoch, uint64(0))
			ls.State = auth.StateFailed
			ls.Err = err
			ctx.Set(constants.CtxKeyLoginStatus, ls)
			ctx.Next()
			return
		}
	}

	ctx.Set(constants.CtxKeyUserID, ls.Claim.UserID)
	ctx.Set(constants.CtxKeyUIN, ls.Claim.UIN)
	ctx.Set(constants.CtxKeyCompanyID, ls.Claim.CompanyID)
	if browser {
		ctx.Set(constants.CtxKeyMembershipEpoch, ls.Claim.MembershipEpoch)
	}
	ctx.Next()
}
