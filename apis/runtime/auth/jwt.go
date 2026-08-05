package auth

import (
	"fmt"

	"github.com/JUXON-AI/jxpkg/config"
)

var jwtSecrets = map[string][]byte{}

// RegisterJwtSecret 注册指定 issuer 的 JWT 签名密钥。
func RegisterJwtSecret(issuer string, secret string) {
	jwtSecrets[issuer] = []byte(secret)
}

// GetJwtSecret 获取指定 issuer 的 JWT 签名密钥。未注册时使用配置中的全局密钥。
func GetJwtSecret(issuer string) ([]byte, error) {
	if secret, ok := jwtSecrets[issuer]; ok {
		return secret, nil
	}
	jwtConf := config.Conf().MainConf.JWT
	if jwtConf.Secret != "" {
		return []byte(jwtConf.Secret), nil
	}
	return []byte(""), fmt.Errorf("jwt secret for issuer %s not found", issuer)
}
