package identity

import (
	"context"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// 本次原生授权输入契约沿用 128 个 Unicode rune 作为部门及祖先 ID 的校验上限。
	_maximumDepartmentIDRunes = 128
	// 本次原生授权输入契约沿用 128 个 Unicode rune 作为显式权限名称的校验上限。
	_maximumPermissionRunes = 128
)

// Department 表示原生组织目录中的一个部门及其有向祖先链。
type Department struct {
	// ID 来自权威目录，必须属于 Authorization.Member 所在组织，不转换为数字标识。
	ID string `json:"id"`
	// AncestorIDs 来自同一组织的权威目录，不包含部门自身，保留生产者提供的顺序。
	AncestorIDs []string `json:"ancestor_ids"`
}

// Authorization 表示一次已验证目录快照中的成员授权；它不推断组织或权限。
type Authorization struct {
	// Member 来自已验证会话或服务端权威记录，是本授权唯一的组织及用户作用域。
	Member Member
	// IsOrganizationOwner 来自该组织的权威目录，不隐含授予 Permissions 或 company:owner。
	IsOrganizationOwner bool
	// Departments 来自权威目录，均须属于 Member 所在组织；部门归属不隐含授予 Permissions。
	Departments []Department
	// Permissions 是 Member 所在组织权威授予的显式权限，区分大小写，不由 owner 或部门隐含继承。
	Permissions []string
}

// Allows 判断授权中是否明确包含指定平台权限。权限区分大小写且不继承。
func (value Authorization) Allows(permission string) bool {
	if !validAuthorization(value) || permission == "" {
		return false
	}
	for _, granted := range value.Permissions {
		if granted == permission {
			return true
		}
	}
	return false
}

type authorizationContextKey struct{}

type authorizationContextValue struct {
	value Authorization
	valid bool
}

// WithAuthorization 将授权写入派生 context；输入切片会被深复制。
func WithAuthorization(ctx context.Context, value Authorization) context.Context {
	stored := cloneAuthorization(value)
	return context.WithValue(ctx, authorizationContextKey{}, authorizationContextValue{
		value: stored,
		valid: validAuthorization(value),
	})
}

// AuthorizationFromContext 返回当前 context 中有效的授权副本；无效授权按不存在处理。
func AuthorizationFromContext(ctx context.Context) (Authorization, bool) {
	if ctx == nil {
		return Authorization{}, false
	}
	stored, ok := ctx.Value(authorizationContextKey{}).(authorizationContextValue)
	if !ok || !stored.valid {
		return Authorization{}, false
	}
	return cloneAuthorization(stored.value), true
}

func validAuthorization(value Authorization) bool {
	if value.Member.Validate() != nil {
		return false
	}
	for _, department := range value.Departments {
		if !validAuthorizationText(department.ID, _maximumDepartmentIDRunes) {
			return false
		}
		for _, ancestorID := range department.AncestorIDs {
			if !validAuthorizationText(ancestorID, _maximumDepartmentIDRunes) {
				return false
			}
		}
	}
	for _, permission := range value.Permissions {
		if !validAuthorizationText(permission, _maximumPermissionRunes) {
			return false
		}
	}
	return true
}

func validAuthorizationText(value string, limit int) bool {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > limit || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func cloneAuthorization(value Authorization) Authorization {
	departments := slices.Clone(value.Departments)
	for index := range departments {
		departments[index].AncestorIDs = slices.Clone(departments[index].AncestorIDs)
	}
	return Authorization{
		Member:              value.Member,
		IsOrganizationOwner: value.IsOrganizationOwner,
		Departments:         departments,
		Permissions:         slices.Clone(value.Permissions),
	}
}
