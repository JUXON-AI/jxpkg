package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// UserClaims JWT 自定义 Claims，兼容旧版短字段并支持标准注册声明。
type UserClaims struct {
	// RegisteredClaims 保存新版非对称令牌使用的标准 JWT 注册声明。
	jwt.RegisteredClaims

	// UserID 表示系统全局用户 ID。
	UserID uint `json:"c,omitempty"`

	// UIN 表示当前选择的公司身份 ID。
	UIN uint `json:"u,omitempty"`

	// CompanyID 表示当前选择的公司 ID。
	CompanyID uint `json:"o,omitempty"`

	// MembershipEpoch 表示令牌绑定的成员身份代次，旧令牌缺失时为零。
	MembershipEpoch uint64 `json:"m,omitempty"`

	// IssuedAt 表示旧版 HS256 令牌签发 Unix 时间戳。
	IssuedAt int64 `json:"t,omitempty"`

	// ExpiresAt 表示旧版 HS256 令牌过期 Unix 时间戳。
	ExpiresAt int64 `json:"e,omitempty"`

	// Audience 表示旧版 HS256 令牌受众。
	Audience string `json:"a,omitempty"`

	// AuthorizedParty 表示多受众令牌的授权方客户端标识。
	AuthorizedParty string `json:"azp,omitempty"`

	// LoginWay 表示用户完成认证的方式。
	LoginWay LoginWay `json:"l,omitempty"`
}

// GetExpirationTime 返回标准过期时间，并为旧版 HS256 令牌保留短字段回退。
func (c *UserClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.RegisteredClaims.ExpiresAt != nil {
		return c.RegisteredClaims.ExpiresAt, nil
	}
	if c.ExpiresAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

// GetIssuedAt 返回标准签发时间，并为旧版 HS256 令牌保留短字段回退。
func (c *UserClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.RegisteredClaims.IssuedAt != nil {
		return c.RegisteredClaims.IssuedAt, nil
	}
	if c.IssuedAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

// GetNotBefore 返回标准生效时间。
func (c *UserClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return c.RegisteredClaims.NotBefore, nil
}

// GetIssuer 返回标准签发方。
func (c *UserClaims) GetIssuer() (string, error) {
	return c.RegisteredClaims.Issuer, nil
}

// GetSubject 返回标准主体。
func (c *UserClaims) GetSubject() (string, error) {
	return c.RegisteredClaims.Subject, nil
}

// GetAudience 返回标准受众，并为旧版 HS256 令牌保留短字段回退。
func (c *UserClaims) GetAudience() (jwt.ClaimStrings, error) {
	if len(c.RegisteredClaims.Audience) != 0 {
		return c.RegisteredClaims.Audience, nil
	}
	if c.Audience == "" {
		return nil, nil
	}
	return jwt.ClaimStrings{c.Audience}, nil
}
