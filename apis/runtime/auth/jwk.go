package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sort"
)

const (
	// jwkKeyTypeOKP 表示 RFC 8037 定义的 Octet Key Pair 密钥类型。
	jwkKeyTypeOKP = "OKP"

	// jwkCurveEd25519 表示 JWK 使用 Ed25519 曲线。
	jwkCurveEd25519 = "Ed25519"

	// jwkUseSignature 表示 JWK 仅用于签名验证。
	jwkUseSignature = "sig"
)

// JSONWebKey 是可公开发布的 Ed25519 JWK 投影。
type JSONWebKey struct {
	// KeyType 表示固定为 OKP 的密钥类型。
	KeyType string `json:"kty"`

	// Curve 表示固定为 Ed25519 的曲线。
	Curve string `json:"crv"`

	// X 表示无填充 Base64URL 编码的 Ed25519 公钥。
	X string `json:"x"`

	// KeyID 表示验证器选择本地公钥使用的稳定标识。
	KeyID string `json:"kid"`

	// Algorithm 表示固定为 EdDSA 的算法。
	Algorithm string `json:"alg"`

	// Use 表示该公钥仅用于签名验证。
	Use string `json:"use"`
}

// JSONWebKeySet 是只包含公钥材料的 JWKS 文档。
type JSONWebKeySet struct {
	// Keys 保存按 kid 字典序排列的公开 JWK。
	Keys []JSONWebKey `json:"keys"`
}

// PublicJWKS 将本地 Ed25519 验证密钥确定性投影为公钥 JWKS。
func PublicJWKS(keys []VerificationKey) (JSONWebKeySet, error) {
	projected := make([]JSONWebKey, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		normalized, err := normalizeVerificationKey(key)
		if err != nil {
			return JSONWebKeySet{}, err
		}
		if _, exists := seen[normalized.KeyID]; exists {
			return JSONWebKeySet{}, fmt.Errorf("%w: duplicate verification key id %q", ErrAuthBackendUnavailable, normalized.KeyID)
		}
		seen[normalized.KeyID] = struct{}{}
		publicKey := normalized.PublicKey.(ed25519.PublicKey)
		projected = append(projected, JSONWebKey{
			KeyType:   jwkKeyTypeOKP,
			Curve:     jwkCurveEd25519,
			X:         base64.RawURLEncoding.EncodeToString(publicKey),
			KeyID:     normalized.KeyID,
			Algorithm: JWTAlgorithmEdDSA,
			Use:       jwkUseSignature,
		})
	}
	sort.Slice(projected, func(i, j int) bool {
		return projected[i].KeyID < projected[j].KeyID
	})
	return JSONWebKeySet{Keys: projected}, nil
}

// JWKS 返回验证器当前轮换重叠集合的确定性公钥投影。
func (v *TokenVerifier) JWKS() (JSONWebKeySet, error) {
	if v == nil || len(v.keys) == 0 {
		return JSONWebKeySet{}, fmt.Errorf("%w: token verifier is not configured", ErrAuthBackendUnavailable)
	}
	keys := make([]VerificationKey, 0, len(v.keys))
	for _, key := range v.keys {
		keys = append(keys, key)
	}
	return PublicJWKS(keys)
}
