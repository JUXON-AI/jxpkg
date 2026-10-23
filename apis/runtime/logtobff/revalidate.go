package logtobff

import (
	"context"
	"errors"
	"time"
)

type (
	revalidationKey        struct{}
	resourceGrantRevokeKey struct{}
)

// resourceGrantRevokeCapability is intentionally concrete and unexported so
// package-external contexts cannot satisfy the capability with a bare func.
type resourceGrantRevokeCapability struct {
	runtime   *Runtime
	id        string
	principal Principal
}

// ErrAuthorizationChanged 表示当前浏览器会话、组织身份或权限已经失效。
var ErrAuthorizationChanged = errors.New("current organization authorization changed")

// ErrUnavailable 表示无法在线确认授权，调用方必须拒绝返回敏感结果。
var ErrUnavailable = errors.New("authorization authority unavailable")

// Revalidate 在返回凭证明文等敏感结果前重新确认当前会话，不从请求体补充主体。
func Revalidate(ctx context.Context) error {
	check, ok := ctx.Value(revalidationKey{}).(func(context.Context) error)
	if !ok {
		return ErrAuthorizationChanged
	}
	return check(ctx)
}

// RevokeResourceGrant revokes one native resource grant owned by the current
// browser session. The request-bound capability is installed only after a
// successful RequireBrowserSession check and revalidates that same session at
// call time; it never exposes the user's access token to the caller.
// jxlog:nonbusiness 本函数只分派已验证的私有能力，业务链路由该能力记录。
func RevokeResourceGrant(ctx context.Context, resource, grantID string) error {
	capability, ok := ctx.Value(resourceGrantRevokeKey{}).(*resourceGrantRevokeCapability)
	if !ok || capability == nil || capability.runtime == nil {
		return ErrAuthorizationChanged
	}
	return capability.revoke(ctx, resource, grantID)
}

// jxlog:nonbusiness 私有适配器只转发已由浏览器 Session 生成的绑定状态。
func (c *resourceGrantRevokeCapability) revoke(ctx context.Context, resource, grantID string) error {
	return c.runtime.revokeResourceGrant(ctx, c.id, c.principal, resource, grantID)
}

func (a *Runtime) revalidate(ctx context.Context, id string, expected Principal, scopes []string) error {
	if a.config.APIResource == "" {
		return a.revalidateIdentity(ctx, id, expected, scopes)
	}
	ctx, cancel := context.WithTimeout(ctx, _authenticationTimeout)
	defer cancel()
	value, owner, err := a.store.acquire(ctx, id)
	if err != nil {
		if errors.Is(err, _errMissing) {
			return ErrAuthorizationChanged
		}
		return ErrUnavailable
	}
	defer a.store.release(ctx, id, owner)
	originalOrganization, originalRevision := value.Organization, value.Revision
	valid := value.Subject == expected.UserID && value.Organization == expected.OrganizationID && value.Revision == expected.OrganizationRevision
	if valid {
		_, _, err = a.currentRequest(ctx, value)
		valid = valid && value.Organization == expected.OrganizationID && value.Revision == expected.OrganizationRevision
		if err == nil {
			var claims *signedClaims
			claims, err = a.organizationClaims(ctx, value, value.Organization)
			if err == nil {
				for _, scope := range scopes {
					if !hasScope(claims, scope) {
						valid = false
					}
				}
			}
		}
	}
	remove := false
	if value.Organization != expected.OrganizationID || value.Revision != expected.OrganizationRevision {
		// This path cannot send a replacement Cookie; leave adoption to the next session request.
		value.Organization, value.Revision = originalOrganization, originalRevision
	}
	if err != nil {
		var denied *accessError
		if errors.As(err, &denied) {
			remove = denied.status == 401
		} else {
			value.Organization = ""
		}
	}
	commit, cancelCommit := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancelCommit()
	if a.store.commit(commit, id, owner, id, value, remove) != nil {
		return ErrUnavailable
	}
	if err != nil {
		var denied *accessError
		if !errors.As(err, &denied) {
			return ErrUnavailable
		}
		return ErrAuthorizationChanged
	}
	if !valid {
		return ErrAuthorizationChanged
	}
	return nil
}
