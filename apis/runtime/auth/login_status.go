package auth

import (
	"github.com/gin-gonic/gin"
)

const (
	// AuthBearer Bearer Token 前缀。
	AuthBearer       = "Bearer "
	// AuthAPIKeyPrefix API Key 前缀。
	AuthAPIKeyPrefix = "goar-"
)

// InjectorFunc 登录状态注入函数，可在认证通过后补充用户信息。
type InjectorFunc func(ctx *gin.Context, ls *LoginStatus) error

// State 登录状态枚举。
type State int

const (
	StateNil    State = 0 // 未认证
	StateSucc   State = 1 // 认证成功
	StateFailed State = 2 // 认证失败
)

// Role 登录角色枚举。
type Role int

const (
	RoleNil Role = iota
	RoleUser
	RoleEmployee
	RoleAPI
)

// LoginStatus 请求的登录态信息。
type LoginStatus struct {
	Token  string
	Claim  *UserClaims
	Err    error
	Role   Role
	State  State
	idmap  map[string]uint
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