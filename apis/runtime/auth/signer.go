package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"reflect"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// JWTAlgorithmEdDSA 表示新 JWT API 唯一允许的 EdDSA 算法。
	JWTAlgorithmEdDSA = "EdDSA"

	// tokenTypeJWT 是非对称令牌必须使用的 typ 头值。
	tokenTypeJWT = "JWT"
)

// TokenSigner 使用一个当前活动的 Ed25519 私钥签发令牌。
type TokenSigner struct {
	// keyID 保存写入 JWT kid 头的活动密钥标识。
	keyID string

	// privateKey 保存活动 Ed25519 私钥的独立副本。
	privateKey ed25519.PrivateKey
}

// NewTokenSigner 使用活动 Ed25519 私钥创建签发器。
func NewTokenSigner(keyID string, privateKey ed25519.PrivateKey) (*TokenSigner, error) {
	if strings.TrimSpace(keyID) == "" || keyID != strings.TrimSpace(keyID) {
		return nil, fmt.Errorf("%w: signing key id must be a non-empty canonical value", ErrAuthBackendUnavailable)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: signing key %q must be an Ed25519 private key", ErrAuthBackendUnavailable, keyID)
	}
	canonicalKey := ed25519.NewKeyFromSeed(privateKey.Seed())
	if subtle.ConstantTimeCompare(privateKey, canonicalKey) != 1 {
		return nil, fmt.Errorf("%w: signing key %q has an inconsistent Ed25519 public component", ErrAuthBackendUnavailable, keyID)
	}
	return &TokenSigner{
		keyID:      keyID,
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
	}, nil
}

// GenerateTokenSigner 使用 crypto/rand 生成新的活动 Ed25519 密钥对。
func GenerateTokenSigner(keyID string) (*TokenSigner, VerificationKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, VerificationKey{}, fmt.Errorf("generate Ed25519 key: %w", err)
	}
	signer, err := NewTokenSigner(keyID, privateKey)
	if err != nil {
		return nil, VerificationKey{}, err
	}
	return signer, VerificationKey{
		KeyID:     keyID,
		Algorithm: JWTAlgorithmEdDSA,
		PublicKey: publicKey,
	}, nil
}

// VerificationKey 返回与活动私钥对应的公钥副本。
func (s *TokenSigner) VerificationKey() VerificationKey {
	if s == nil || len(s.privateKey) != ed25519.PrivateKeySize {
		return VerificationKey{}
	}
	publicKey := s.privateKey.Public().(ed25519.PublicKey)
	return VerificationKey{
		KeyID:     s.keyID,
		Algorithm: JWTAlgorithmEdDSA,
		PublicKey: append(ed25519.PublicKey(nil), publicKey...),
	}
}

// Sign 使用 EdDSA 签发 claims，并返回原始令牌和活动 kid。
func (s *TokenSigner) Sign(ctx context.Context, claims jwt.Claims) (raw, keyID string, err error) {
	if err := contextError(ctx); err != nil {
		return "", "", err
	}
	if s == nil || strings.TrimSpace(s.keyID) == "" || len(s.privateKey) != ed25519.PrivateKeySize {
		return "", "", fmt.Errorf("%w: token signer is not configured", ErrAuthBackendUnavailable)
	}
	if claims == nil || isNilClaims(claims) {
		return "", "", fmt.Errorf("sign jwt: claims are nil")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"] = tokenTypeJWT
	token.Header["kid"] = s.keyID
	raw, err = token.SignedString(s.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("sign jwt: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return "", "", err
	}
	return raw, s.keyID, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is nil")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func isNilClaims(claims jwt.Claims) bool {
	value := reflect.ValueOf(claims)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
