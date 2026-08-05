package server

import (
	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
)

type authInjectors struct {
	injectors       map[string]auth.InjectorFunc
	defaultInjector auth.InjectorFunc
}

// AuthInject 为指定 issuer 注册认证注入函数。
func (ai *authInjectors) AuthInject(issuer string, injector auth.InjectorFunc) {
	ai.injectors[issuer] = injector
}

// Default 设置默认认证注入函数（issuer 未匹配时使用）。
func (ai *authInjectors) Default(injector auth.InjectorFunc) {
	ai.defaultInjector = injector
}

// Inject 根据请求的登录态执行对应的认证注入。
func (ai *authInjectors) Inject(ctx *gin.Context) {
	val, ok := ctx.Get(constants.CtxKeyLoginStatus)
	if !ok {
		ctx.Next()
		return
	}
	ls, ok := val.(*auth.LoginStatus)
	if !ok || ls.State != auth.StateSucc {
		ctx.Next()
		return
	}

	var injector auth.InjectorFunc
	if ls.Claim != nil && ls.Claim.Issuer != "" {
		injector = ai.injectors[ls.Claim.Issuer]
	}
	if injector == nil {
		injector = ai.defaultInjector
	}
	if injector != nil {
		err := injector(ctx, ls)
		if err != nil {
			ls.State = auth.StateFailed
			ls.Err = err
			ctx.Set(constants.CtxKeyLoginStatus, ls)
		}
	}
	ctx.Next()
}
