package auth

import (
	"errors"

	"github.com/gin-gonic/gin"
)

const (
	// AuthBearer Bearer Token 认证方案。
	AuthBearer = "Bearer"
)

var (
	ErrInvalidCredential      = errors.New("invalid credential")
	ErrInvalidPrincipal       = errors.New("invalid principal")
	ErrAuthBackendUnavailable = errors.New("auth backend unavailable")
)

// InjectorFunc 登录状态注入函数，可在认证通过后补充用户信息。
type InjectorFunc func(ctx *gin.Context, ls *LoginStatus) error

// AuthMode 表示路由唯一允许的认证模式。
type AuthMode string

const (
	// AuthModeAnonymous 表示不解析认证凭据的公开路由。
	AuthModeAnonymous AuthMode = "anonymous"

	// AuthModeBrowserSession 表示仅接受浏览器 Cookie Session 的路由。
	AuthModeBrowserSession AuthMode = "browser_session"

	// AuthModeBearer 表示仅接受 Bearer Token 的路由。
	AuthModeBearer AuthMode = "bearer"

	// AuthModeInternal 表示仅接受内部工作负载身份的路由。
	AuthModeInternal AuthMode = "internal"
)

// State 登录状态枚举。
type State int

const (
	// StateNil 表示请求尚未通过认证。
	StateNil State = 0

	// StateSucc 表示请求已通过认证。
	StateSucc State = 1

	// StateFailed 表示请求认证失败。
	StateFailed State = 2
)

// Role 登录角色枚举。
type Role int

const (
	// RoleNil 表示尚未设置登录角色。
	RoleNil Role = iota

	// RoleUser 表示普通用户角色。
	RoleUser

	// RoleEmployee 表示员工角色。
	RoleEmployee

	// RoleAPI 表示 API 调用方角色。
	RoleAPI
)

// LoginStatus 请求的登录态信息。
type LoginStatus struct {
	// Claim 保存认证主体声明。
	Claim *UserClaims

	// Err 保存认证失败原因。
	Err error

	// Role 保存业务注入器确认的登录角色。
	Role Role

	// State 保存当前认证状态。
	State State

	// AuthMode 保存服务端路由选择的唯一认证模式。
	AuthMode AuthMode

	// session 保存不可变的浏览器会话元数据。
	session SessionMetadata

	// idmap 保存业务注入器补充的额外 ID。
	idmap map[string]uint
}

// NewBrowserSessionLoginStatus 从已验证的会话主体创建浏览器登录状态。
func NewBrowserSessionLoginStatus(principal SessionPrincipal) *LoginStatus {
	claims := principal.Claims
	return &LoginStatus{
		Claim:    &claims,
		State:    StateSucc,
		AuthMode: AuthModeBrowserSession,
		session:  NewSessionMetadata(principal),
	}
}

// SessionMetadata 返回不可变的浏览器会话元数据。
func (ls *LoginStatus) SessionMetadata() SessionMetadata {
	if ls == nil {
		return SessionMetadata{}
	}
	return ls.session
}

// SetID 存储额外 ID（如 company_id、employee_id）。
func (ls *LoginStatus) SetID(idname string, id uint) {
	if ls.idmap == nil {
		ls.idmap = map[string]uint{}
	}
	ls.idmap[idname] = id
}

// GetID 读取之前存储的额外 ID。
func (ls *LoginStatus) GetID(idname string) uint {
	return ls.idmap[idname]
}
