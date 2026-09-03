package auth

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// VerificationKey 描述一个固定算法和标识的 JWT 验证公钥。
type VerificationKey struct {
	// KeyID 表示与 JWT kid 头精确匹配的密钥标识。
	KeyID string

	// Algorithm 表示该密钥唯一允许的 JWT 签名算法。
	Algorithm string

	// PublicKey 表示仅用于验证的 Ed25519 公钥。
	PublicKey crypto.PublicKey
}

// TokenVerifier 定义新代码使用的非对称 JWT 验证边界。
type TokenVerifier interface {
	Verify(ctx context.Context, raw, expectedIssuer, expectedAudience string) (*UserClaims, error)
}

// Ed25519TokenVerifier 使用本地固定公钥集合验证 EdDSA 令牌。
type Ed25519TokenVerifier struct {
	// keys 保存按 kid 索引的不可变验证密钥副本。
	keys map[string]VerificationKey
}

// NewTokenVerifier 创建支持密钥轮换重叠窗口的本地验证器。
func NewTokenVerifier(keys []VerificationKey) (*Ed25519TokenVerifier, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: verification keys are empty", ErrAuthBackendUnavailable)
	}
	indexed := make(map[string]VerificationKey, len(keys))
	for _, key := range keys {
		normalized, err := normalizeVerificationKey(key)
		if err != nil {
			return nil, err
		}
		if _, exists := indexed[normalized.KeyID]; exists {
			return nil, fmt.Errorf("%w: duplicate verification key id %q", ErrAuthBackendUnavailable, normalized.KeyID)
		}
		indexed[normalized.KeyID] = normalized
	}
	return &Ed25519TokenVerifier{keys: indexed}, nil
}

// Verify 严格验证 EdDSA 令牌、标准声明和预期签发方及受众。
func (v *Ed25519TokenVerifier) Verify(ctx context.Context, raw, expectedIssuer, expectedAudience string) (*UserClaims, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if v == nil || len(v.keys) == 0 {
		return nil, fmt.Errorf("%w: token verifier is not configured", ErrAuthBackendUnavailable)
	}
	if strings.TrimSpace(raw) == "" || strings.TrimSpace(expectedIssuer) == "" || strings.TrimSpace(expectedAudience) == "" {
		return nil, ErrInvalidCredential
	}
	if err := validateCompactJSONObjects(raw); err != nil {
		return nil, invalidCredential("verify jwt", err)
	}

	claims := new(UserClaims)
	token, err := jwt.ParseWithClaims(
		raw,
		claims,
		v.verificationKey,
		jwt.WithValidMethods([]string{JWTAlgorithmEdDSA}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithIssuer(expectedIssuer),
		jwt.WithAudience(expectedAudience),
		jwt.WithJSONNumber(),
		jwt.WithStrictDecoding(),
	)
	if err != nil {
		return nil, invalidCredential("verify jwt", err)
	}
	if !token.Valid || !validRequiredClaims(claims, expectedAudience) {
		return nil, ErrInvalidCredential
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *Ed25519TokenVerifier) verificationKey(token *jwt.Token) (any, error) {
	if token == nil || token.Method != jwt.SigningMethodEdDSA || token.Method.Alg() != JWTAlgorithmEdDSA {
		return nil, fmt.Errorf("unexpected signing method")
	}
	if len(token.Header) != 3 {
		return nil, fmt.Errorf("unexpected JWT headers")
	}
	if typ, ok := token.Header["typ"].(string); !ok || typ != tokenTypeJWT {
		return nil, fmt.Errorf("invalid typ header")
	}
	if _, exists := token.Header["jku"]; exists {
		return nil, fmt.Errorf("jku header is forbidden")
	}
	if _, exists := token.Header["x5u"]; exists {
		return nil, fmt.Errorf("x5u header is forbidden")
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || strings.TrimSpace(kid) == "" || kid != strings.TrimSpace(kid) {
		return nil, fmt.Errorf("invalid kid header")
	}
	key, ok := v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown kid")
	}
	if key.Algorithm != JWTAlgorithmEdDSA {
		return nil, fmt.Errorf("key algorithm mismatch")
	}
	publicKey, ok := key.PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("key type mismatch")
	}
	return publicKey, nil
}

func normalizeVerificationKey(key VerificationKey) (VerificationKey, error) {
	if strings.TrimSpace(key.KeyID) == "" || key.KeyID != strings.TrimSpace(key.KeyID) {
		return VerificationKey{}, fmt.Errorf("%w: verification key id must be a non-empty canonical value", ErrAuthBackendUnavailable)
	}
	if key.Algorithm != JWTAlgorithmEdDSA {
		return VerificationKey{}, fmt.Errorf("%w: verification key %q must use EdDSA", ErrAuthBackendUnavailable, key.KeyID)
	}
	publicKey, ok := key.PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return VerificationKey{}, fmt.Errorf("%w: verification key %q must be an Ed25519 public key", ErrAuthBackendUnavailable, key.KeyID)
	}
	return VerificationKey{
		KeyID:     key.KeyID,
		Algorithm: key.Algorithm,
		PublicKey: append(ed25519.PublicKey(nil), publicKey...),
	}, nil
}

func validRequiredClaims(claims *UserClaims, expectedAudience string) bool {
	if claims == nil || !isCanonicalClaimValue(claims.RegisteredClaims.Issuer) ||
		!isCanonicalClaimValue(claims.RegisteredClaims.Subject) ||
		claims.RegisteredClaims.IssuedAt == nil || claims.RegisteredClaims.ExpiresAt == nil ||
		!isCanonicalClaimValue(claims.RegisteredClaims.ID) || len(claims.RegisteredClaims.Audience) == 0 {
		return false
	}
	seenAudiences := make(map[string]struct{}, len(claims.RegisteredClaims.Audience))
	for _, audience := range claims.RegisteredClaims.Audience {
		if !isCanonicalClaimValue(audience) {
			return false
		}
		if _, exists := seenAudiences[audience]; exists {
			return false
		}
		seenAudiences[audience] = struct{}{}
	}
	if len(seenAudiences) > 1 && claims.AuthorizedParty != expectedAudience {
		return false
	}
	return true
}

func isCanonicalClaimValue(value string) bool {
	return strings.TrimSpace(value) != "" && value == strings.TrimSpace(value)
}

func invalidCredential(operation string, err error) error {
	return fmt.Errorf("%w: %s: %v", ErrInvalidCredential, operation, err)
}
