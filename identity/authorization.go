package identity

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maximumDepartmentIDRunes = 128
	maximumPermissionRunes   = 128
)

// Department 表示原生组织目录中的一个部门及其有向祖先链。
type Department struct {
	ID          string   `json:"id"`
	AncestorIDs []string `json:"ancestor_ids"`
}

// Authorization 表示一次已验证目录快照中的成员授权；它不推断组织或权限。
type Authorization struct {
	Member              Member
	IsOrganizationOwner bool
	Departments         []Department
	Permissions         []string
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
		if !validAuthorizationText(department.ID, maximumDepartmentIDRunes) {
			return false
		}
		for _, ancestorID := range department.AncestorIDs {
			if !validAuthorizationText(ancestorID, maximumDepartmentIDRunes) {
				return false
			}
		}
	}
	for _, permission := range value.Permissions {
		if !validAuthorizationText(permission, maximumPermissionRunes) {
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
	departments := cloneSlice(value.Departments)
	for index := range departments {
		departments[index].AncestorIDs = cloneSlice(departments[index].AncestorIDs)
	}
	return Authorization{
		Member:              value.Member,
		IsOrganizationOwner: value.IsOrganizationOwner,
		Departments:         departments,
		Permissions:         cloneSlice(value.Permissions),
	}
}

func cloneSlice[T any](value []T) []T {
	if value == nil {
		return nil
	}
	return append([]T{}, value...)
}
