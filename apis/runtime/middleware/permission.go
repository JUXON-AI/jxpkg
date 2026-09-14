package middleware

import (
	"errors"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
)

// PermissionFailureHandler 将权限拒绝或授权服务故障转换为业务服务的响应协议。
type PermissionFailureHandler func(*gin.Context, error)

// ResolveAuthorizationContext 解析一次请求所需的组织权限和部门上下文。
func ResolveAuthorizationContext(
	resolver auth.AuthorizationContextResolver,
	service string,
	permissions []auth.PermissionCode,
	onFailure PermissionFailureHandler,
) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if resolver == nil || service == "" || onFailure == nil {
			ctx.Abort()
			return
		}
		companyID := ctx.GetUint(constants.CtxKeyCompanyID)
		uin := ctx.GetUint(constants.CtxKeyUIN)
		membershipEpoch := ctx.GetUint64(constants.CtxKeyMembershipEpoch)
		result, err := resolver.ResolveAuthorizationContext(ctx.Request.Context(), auth.AuthorizationContextResolveRequest{
			Service:         service,
			CompanyID:       companyID,
			UIN:             uin,
			MembershipEpoch: membershipEpoch,
			Permissions:     append([]auth.PermissionCode(nil), permissions...),
		})
		if err != nil {
			ctx.Abort()
			onFailure(ctx, err)
			return
		}
		if result == nil || result.CompanyID != companyID || result.UIN != uin || result.MembershipEpoch != membershipEpoch {
			ctx.Abort()
			onFailure(ctx, errors.New("authorization resolver returned a mismatched context"))
			return
		}
		ctx.Set(constants.CtxKeyAuthorizationContext, result)
		ctx.Next()
	}
}

// RequirePermission 要求上游已解析的授权上下文包含指定组织权限。
func RequirePermission(permission auth.PermissionCode, onFailure PermissionFailureHandler) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		value, exists := ctx.Get(constants.CtxKeyAuthorizationContext)
		result, ok := value.(*auth.AuthorizationContextResolveResponse)
		if !exists || !ok || result == nil || permission == "" || onFailure == nil {
			ctx.Abort()
			return
		}
		if result.Allows(permission) {
			ctx.Next()
			return
		}
		ctx.Abort()
		onFailure(ctx, auth.ErrAuthorizationDenied)
	}
}

// AuthorizationUnavailable 判断授权失败是否来自不可用的权威服务。
func AuthorizationUnavailable(err error) bool {
	return err != nil && !errors.Is(err, auth.ErrAuthorizationDenied)
}
