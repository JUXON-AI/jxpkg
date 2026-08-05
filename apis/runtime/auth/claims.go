package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// UserClaims JWT 自定义 Claims，包含用户 Uin、签发时间、过期时间等信息。
type UserClaims struct {
	Uin       uint     `json:"c,omitempty"`
	IssuedAt  int64    `json:"t,omitempty"`
	ExpiresAt int64    `json:"e,omitempty"`
	Issuer    string   `json:"i,omitempty"`
	Audience  string   `json:"a,omitempty"`
	LoginWay  LoginWay `json:"l,omitempty"`
}

// Valid 校验 JWT 是否在有效期内。
func (c UserClaims) Valid() error {
	now := time.Now().Unix()
	if c.IssuedAt > now {
		return fmt.Errorf("token used before issued")
	}
	if c.ExpiresAt < now {
		return fmt.Errorf("token is expired")
	}
	return nil
}

// GetExpirationTime 返回过期时间。
func (c *UserClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

// GetIssuedAt 返回签发时间。
func (c *UserClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

func (c *UserClaims) GetNotBefore() (*jwt.NumericDate, error) { return nil, nil }
func (c *UserClaims) GetIssuer() (string, error)              { return c.Issuer, nil }
func (c *UserClaims) GetSubject() (string, error)             { return "", nil }
func (c *UserClaims) GetAudience() (jwt.ClaimStrings, error) {
	if c.Audience == "" {
		return nil, nil
	}
	return jwt.ClaimStrings{c.Audience}, nil
}