package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// UserClaims JWT 自定义 Claims，包含用户 ID、签发时间、过期时间等信息。
type UserClaims struct {
	// UserID 表示系统全局用户 ID。
	UserID uint `json:"c,omitempty"`

	// UIN 表示当前选择的公司身份 ID。
	UIN uint `json:"u,omitempty"`

	// CompanyID 表示当前选择的公司 ID。
	CompanyID uint `json:"o,omitempty"`

	// MembershipEpoch 表示令牌绑定的成员身份代次，旧令牌缺失时为零。
	MembershipEpoch uint64 `json:"m,omitempty"`

	// IssuedAt 表示令牌签发 Unix 时间戳。
	IssuedAt int64 `json:"t,omitempty"`

	// ExpiresAt 表示令牌过期 Unix 时间戳。
	ExpiresAt int64 `json:"e,omitempty"`

	// Audience 表示令牌受众。
	Audience string `json:"a,omitempty"`

	// LoginWay 表示用户完成认证的方式。
	LoginWay LoginWay `json:"l,omitempty"`
}

// GetExpirationTime 返回过期时间。
func (c *UserClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.ExpiresAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

// GetIssuedAt 返回签发时间。
func (c *UserClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.IssuedAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

func (c *UserClaims) GetNotBefore() (*jwt.NumericDate, error) { return nil, nil }
func (c *UserClaims) GetIssuer() (string, error)              { return "", nil }
func (c *UserClaims) GetSubject() (string, error)             { return "", nil }
func (c *UserClaims) GetAudience() (jwt.ClaimStrings, error) {
	if c.Audience == "" {
		return nil, nil
	}
	return jwt.ClaimStrings{c.Audience}, nil
}
