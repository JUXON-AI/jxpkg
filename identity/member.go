// Package identity 定义服务间共享的身份值，不创建会话、不推断组织，也不授予权限。
package identity

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrInvalidMember 表示成员标识缺失或格式不合法，不代表已经执行过权限检查。
var ErrInvalidMember = errors.New("invalid organization member")

// Member 是组织内的成员标识；同一 UserID 在不同组织中是不同的业务主体。
type Member struct {
	// OrganizationID 由验证过的会话或服务端权威记录提供。
	OrganizationID string `json:"organization_id"`
	// UserID 保留完整 Logto 用户标识，不转换为数字 UIN。
	UserID string `json:"user_id"`
}

// Validate 验证规范格式，不裁剪、转换标识，也不查询成员是否仍有准入资格。
func (s Member) Validate() error {
	for _, field := range []struct {
		value string
		limit int
	}{{s.OrganizationID, 64}, {s.UserID, 128}} {
		if field.value == "" || !utf8.ValidString(field.value) || utf8.RuneCountInString(field.value) > field.limit || strings.TrimSpace(field.value) != field.value {
			return ErrInvalidMember
		}
		for _, character := range field.value {
			if unicode.IsControl(character) {
				return ErrInvalidMember
			}
		}
	}
	return nil
}
