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

// JWTConfig JWT 签名配置。
type JWTConfig struct {
	// Secret 表示 HS256 签名密钥，至少需要 32 字节。
	Secret string `yaml:"secret"`

	// Expire 表示访问令牌有效期。
	Expire time.Duration `yaml:"expire"`
}

var jwtConfig struct {
	sync.RWMutex
	value JWTConfig
}

// LoadJWTConfig 从 settings 加载 JWT 签名密钥和有效期。
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

// IssueIdentityToken 为用户选择的公司身份签发 JWT。
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

// ParseToken 使用已加载的单一密钥验证 JWT。
func ParseToken(rawToken string) (*UserClaims, error) {
	config, err := getJWTConfig()
	if err != nil {
		return nil, err
	}

	claims := new(UserClaims)
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
	return claims, nil
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
