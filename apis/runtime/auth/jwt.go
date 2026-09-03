package auth

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/JUXON-AI/jxpkg/settings"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// jwtSettingGroup 是 JWT 配置所在的 settings 分组。
	jwtSettingGroup = "core"

	// jwtSettingKey 是 JWT 签名配置的 settings 键。
	jwtSettingKey = "jwt-secret"

	// minimumJWTSecretBytes 是 HS256 签名密钥允许的最小字节数。
	minimumJWTSecretBytes = 32
)

// JWTConfig 是仅供迁移期旧版 HS256 API 使用的签名配置。
type JWTConfig struct {
	// Secret 表示旧版 HS256 签名密钥，至少需要 32 字节。
	Secret string `yaml:"secret"`

	// Expire 表示访问令牌有效期。
	Expire time.Duration `yaml:"expire"`
}

var jwtConfig struct {
	sync.RWMutex
	value JWTConfig
}

// LoadJWTConfig 从 settings 加载仅供旧版 HS256 API 使用的签名密钥和有效期。
func LoadJWTConfig() error {
	config := JWTConfig{}
	if err := settings.GetYaml(jwtSettingGroup, jwtSettingKey, &config); err != nil {
		return fmt.Errorf("%w: load %s/%s: %w", ErrAuthBackendUnavailable, jwtSettingGroup, jwtSettingKey, err)
	}
	if err := validateJWTConfig(config); err != nil {
		return err
	}

	setJWTConfig(config)
	return nil
}

func validateJWTConfig(config JWTConfig) error {
	if strings.TrimSpace(config.Secret) == "" {
		return fmt.Errorf("%w: %s/%s is empty", ErrAuthBackendUnavailable, jwtSettingGroup, jwtSettingKey)
	}
	if len(config.Secret) < minimumJWTSecretBytes {
		return fmt.Errorf("%w: %s/%s must be at least %d bytes", ErrAuthBackendUnavailable, jwtSettingGroup, jwtSettingKey, minimumJWTSecretBytes)
	}
	if config.Expire <= 0 {
		return fmt.Errorf("%w: %s/%s expire must be positive", ErrAuthBackendUnavailable, jwtSettingGroup, jwtSettingKey)
	}
	return nil
}

// IssueIdentityToken 使用旧版 HS256 迁移路径为公司身份签发 JWT；浏览器会话不得调用。
func IssueIdentityToken(userID, uin, companyID uint, membershipEpoch uint64, loginWay LoginWay) (string, int64, error) {
	if uin == 0 || companyID == 0 {
		return "", 0, ErrInvalidPrincipal
	}
	return issueToken(userID, uin, companyID, membershipEpoch, loginWay)
}

func issueToken(userID, uin, companyID uint, membershipEpoch uint64, loginWay LoginWay) (string, int64, error) {
	if userID == 0 {
		return "", 0, ErrInvalidPrincipal
	}
	if loginWay == LoginWayUnknown {
		return "", 0, ErrInvalidLoginWay
	}

	config, err := getJWTConfig()
	if err != nil {
		return "", 0, err
	}
	now := time.Now()
	expiresAt := now.Add(config.Expire).Unix()
	claims := &UserClaims{
		UserID:          userID,
		UIN:             uin,
		CompanyID:       companyID,
		MembershipEpoch: membershipEpoch,
		IssuedAt:        now.Unix(),
		ExpiresAt:       expiresAt,
		LoginWay:        loginWay,
	}
	rawToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(config.Secret))
	if err != nil {
		return "", 0, fmt.Errorf("sign jwt: %w", err)
	}
	return rawToken, expiresAt, nil
}

// ParseToken 为现有调用保留旧版 HS256 验证入口。
//
// Deprecated: 仅迁移代码可调用 ParseLegacyToken；新代码必须依赖 TokenVerifier。
func ParseToken(rawToken string) (*UserClaims, error) {
	return ParseLegacyToken(rawToken)
}

// ParseLegacyToken 使用旧版 HS256 迁移路径验证 JWT；浏览器会话不得调用。
func ParseLegacyToken(rawToken string) (*UserClaims, error) {
	config, err := getJWTConfig()
	if err != nil {
		return nil, err
	}

	claims := new(legacyUserClaims)
	token, err := jwt.ParseWithClaims(
		rawToken,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("unexpected signing method %s", token.Method.Alg())
			}
			return []byte(config.Secret), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCredential, err)
	}
	if !token.Valid || claims.UserID == 0 || claims.UIN == 0 || claims.CompanyID == 0 || claims.IssuedAt == 0 {
		return nil, ErrInvalidCredential
	}
	parsedClaims := UserClaims(*claims)
	return &parsedClaims, nil
}

// legacyUserClaims 保持旧版 HS256 解析只读取短字段 t、e 和 a。
type legacyUserClaims UserClaims

// GetExpirationTime 返回旧版短字段过期时间。
func (c *legacyUserClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.ExpiresAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

// GetIssuedAt 返回旧版短字段签发时间。
func (c *legacyUserClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.IssuedAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

// GetNotBefore 保持旧版不校验 nbf 的行为。
func (c *legacyUserClaims) GetNotBefore() (*jwt.NumericDate, error) { return nil, nil }

// GetIssuer 保持旧版不读取 iss 的行为。
func (c *legacyUserClaims) GetIssuer() (string, error) { return "", nil }

// GetSubject 保持旧版不读取 sub 的行为。
func (c *legacyUserClaims) GetSubject() (string, error) { return "", nil }

// GetAudience 返回旧版短字段受众。
func (c *legacyUserClaims) GetAudience() (jwt.ClaimStrings, error) {
	if c.Audience == "" {
		return nil, nil
	}
	return jwt.ClaimStrings{c.Audience}, nil
}

func setJWTConfig(config JWTConfig) {
	jwtConfig.Lock()
	defer jwtConfig.Unlock()
	jwtConfig.value = config
}

func getJWTConfig() (JWTConfig, error) {
	jwtConfig.RLock()
	defer jwtConfig.RUnlock()
	if strings.TrimSpace(jwtConfig.value.Secret) == "" || jwtConfig.value.Expire <= 0 {
		return JWTConfig{}, fmt.Errorf("%w: jwt config is not loaded", ErrAuthBackendUnavailable)
	}
	return jwtConfig.value, nil
}
