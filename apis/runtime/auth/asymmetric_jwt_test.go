package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	_ TokenSigner   = (*Ed25519TokenSigner)(nil)
	_ TokenSigner   = fakeTokenSigner{}
	_ TokenVerifier = (*Ed25519TokenVerifier)(nil)
	_ TokenVerifier = fakeTokenVerifier{}
)

const (
	// testIssuer 表示测试令牌的固定签发方。
	testIssuer = "https://issuer.example.com"

	// testAudience 表示测试令牌的固定受众。
	testAudience = "api.example.com"
)

func TestTokenInterfacesAcceptMethodCompatibleFakes(t *testing.T) {
	claims := validAsymmetricClaims(time.Now())
	var signer TokenSigner = fakeTokenSigner{raw: "signed", keyID: "fake-key"}
	raw, keyID, err := signer.Sign(context.Background(), claims)
	if err != nil || raw != "signed" || keyID != "fake-key" {
		t.Fatalf("fake signer result = %q, %q, %v", raw, keyID, err)
	}

	var verifier TokenVerifier = fakeTokenVerifier{claims: claims}
	got, err := verifier.Verify(context.Background(), raw, testIssuer, testAudience)
	if err != nil || got != claims {
		t.Fatalf("fake verifier result = %p, %v, want %p", got, err, claims)
	}
}

func TestTokenVerifierRejectsSignedDuplicateJSONMembers(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	verifier, err := NewTokenVerifier([]VerificationKey{{KeyID: "key-1", Algorithm: JWTAlgorithmEdDSA, PublicKey: privateKey.Public()}})
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}
	now := time.Now()
	validHeader := `{"alg":"EdDSA","typ":"JWT","kid":"key-1"}`
	tests := []struct {
		// name 表示重复 JSON 成员测试用例名称。
		name string

		// header 表示被签名的原始受保护 JOSE 头。
		header string

		// payload 表示被签名的原始 JWT 声明。
		payload string
	}{
		{name: "duplicate kid", header: `{"kid":"wrong","kid":"key-1","alg":"EdDSA","typ":"JWT"}`, payload: validSignedPayload(now, "")},
		{name: "duplicate alg", header: `{"alg":"HS256","alg":"EdDSA","typ":"JWT","kid":"key-1"}`, payload: validSignedPayload(now, "")},
		{name: "duplicate typ", header: `{"typ":"at+jwt","typ":"JWT","alg":"EdDSA","kid":"key-1"}`, payload: validSignedPayload(now, "")},
		{name: "duplicate iss", header: validHeader, payload: validSignedPayload(now, `"iss":"https://wrong.example.com",`)},
		{name: "duplicate aud", header: validHeader, payload: validSignedPayload(now, `"aud":["wrong-api"],`)},
		{name: "duplicate exp", header: validHeader, payload: validSignedPayload(now, `"exp":0,`)},
		{name: "duplicate sub", header: validHeader, payload: validSignedPayload(now, `"sub":"wrong-user",`)},
		{name: "duplicate jti", header: validHeader, payload: validSignedPayload(now, `"jti":"wrong-token",`)},
		{name: "duplicate azp", header: validHeader, payload: validSignedPayload(now, `"azp":"wrong-client","azp":"final-client",`)},
		{name: "nested duplicate", header: validHeader, payload: validSignedPayload(now, `"metadata":{"role":"old","role":"new"},`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := signRawEdDSA(t, privateKey, tt.header, tt.payload)
			if _, err := verifier.Verify(context.Background(), raw, testIssuer, testAudience); !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("Verify error = %v, want ErrInvalidCredential", err)
			}
		})
	}
}

func TestTokenVerifierRejectsSignedInvalidJSONEnvelopes(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	verifier, err := NewTokenVerifier([]VerificationKey{{KeyID: "key-1", Algorithm: JWTAlgorithmEdDSA, PublicKey: privateKey.Public()}})
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}
	now := time.Now()
	validHeader := `{"alg":"EdDSA","typ":"JWT","kid":"key-1"}`
	deepHeader := `{"nested":` + strings.Repeat("[", maximumJSONNestingDepth) + "0" + strings.Repeat("]", maximumJSONNestingDepth) + `,"alg":"EdDSA","typ":"JWT","kid":"key-1"}`
	deepPayload := `{"nested":` + strings.Repeat("[", maximumJSONNestingDepth) + "0" + strings.Repeat("]", maximumJSONNestingDepth) + `,` + strings.TrimPrefix(validSignedPayload(now, ""), "{")
	largeHeader := `{"padding":"` + strings.Repeat("x", maximumJOSEHeaderBytes) + `"}`
	largePayload := `{"padding":"` + strings.Repeat("x", maximumJWTClaimsBytes) + `"}`
	tests := []struct {
		// name 表示无效 JSON 信封测试用例名称。
		name string

		// header 表示被签名的原始受保护 JOSE 头。
		header string

		// payload 表示被签名的原始 JWT 声明。
		payload string
	}{
		{name: "header is not object", header: `[]`, payload: validSignedPayload(now, "")},
		{name: "payload is not object", header: validHeader, payload: `[]`},
		{name: "malformed header", header: `{"alg":`, payload: validSignedPayload(now, "")},
		{name: "malformed payload", header: validHeader, payload: `{"iss":`},
		{name: "invalid UTF-8 payload", header: validHeader, payload: string([]byte{0xff})},
		{name: "excessive header nesting", header: deepHeader, payload: validSignedPayload(now, "")},
		{name: "excessive payload nesting", header: validHeader, payload: deepPayload},
		{name: "excessive header size", header: largeHeader, payload: validSignedPayload(now, "")},
		{name: "excessive payload size", header: validHeader, payload: largePayload},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := signRawEdDSA(t, privateKey, tt.header, tt.payload)
			if _, err := verifier.Verify(context.Background(), raw, testIssuer, testAudience); !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("Verify error = %v, want ErrInvalidCredential", err)
			}
		})
	}
}

func TestTokenVerifierRejectsLegacyHS256(t *testing.T) {
	secret := strings.Repeat("s", minimumJWTSecretBytes)
	setJWTConfig(JWTConfig{Secret: secret, Expire: time.Hour})
	t.Cleanup(func() { setJWTConfig(JWTConfig{}) })
	legacyRaw, _, err := IssueIdentityToken(42, 84, 126, 7, LoginWayEmail)
	if err != nil {
		t.Fatalf("IssueIdentityToken: %v", err)
	}

	_, verificationKey, err := GenerateTokenSigner("key-1")
	if err != nil {
		t.Fatalf("GenerateTokenSigner: %v", err)
	}
	verifier, err := NewTokenVerifier([]VerificationKey{verificationKey})
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), legacyRaw, testIssuer, testAudience); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Verify legacy HS256 error = %v, want ErrInvalidCredential", err)
	}
}

func TestTokenSignerAndVerifier(t *testing.T) {
	signer, verificationKey, err := GenerateTokenSigner("active-2026-09")
	if err != nil {
		t.Fatalf("GenerateTokenSigner: %v", err)
	}
	verifier, err := NewTokenVerifier([]VerificationKey{verificationKey})
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}

	claims := validAsymmetricClaims(time.Now())
	raw, keyID, err := signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if keyID != "active-2026-09" {
		t.Fatalf("keyID = %q, want active-2026-09", keyID)
	}

	got, err := verifier.Verify(context.Background(), raw, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != claims.Subject || got.UserID != claims.UserID || got.ID != claims.ID {
		t.Fatalf("claims = %+v, want subject %q, user %d, jti %q", got, claims.Subject, claims.UserID, claims.ID)
	}

	parsed, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if parsed.Header["alg"] != JWTAlgorithmEdDSA || parsed.Header["typ"] != tokenTypeJWT || parsed.Header["kid"] != keyID {
		t.Fatalf("headers = %#v", parsed.Header)
	}
}

func TestTokenVerifierRotationOverlap(t *testing.T) {
	oldSigner, oldKey, err := GenerateTokenSigner("old")
	if err != nil {
		t.Fatalf("GenerateTokenSigner(old): %v", err)
	}
	activeSigner, activeKey, err := GenerateTokenSigner("active")
	if err != nil {
		t.Fatalf("GenerateTokenSigner(active): %v", err)
	}
	verifier, err := NewTokenVerifier([]VerificationKey{activeKey, oldKey})
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}

	for _, signer := range []*Ed25519TokenSigner{oldSigner, activeSigner} {
		raw, keyID, signErr := signer.Sign(context.Background(), validAsymmetricClaims(time.Now()))
		if signErr != nil {
			t.Fatalf("Sign(%q): %v", keyID, signErr)
		}
		if _, verifyErr := verifier.Verify(context.Background(), raw, testIssuer, testAudience); verifyErr != nil {
			t.Fatalf("Verify(%q): %v", keyID, verifyErr)
		}
	}

	activeOnly, err := NewTokenVerifier([]VerificationKey{activeKey})
	if err != nil {
		t.Fatalf("NewTokenVerifier(active): %v", err)
	}
	oldRaw, _, err := oldSigner.Sign(context.Background(), validAsymmetricClaims(time.Now()))
	if err != nil {
		t.Fatalf("Sign(old): %v", err)
	}
	if _, err := activeOnly.Verify(context.Background(), oldRaw, testIssuer, testAudience); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Verify retired key error = %v, want ErrInvalidCredential", err)
	}
}

func TestTokenVerifierRejectsInvalidTokens(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	verifier, err := NewTokenVerifier([]VerificationKey{{KeyID: "key-1", Algorithm: JWTAlgorithmEdDSA, PublicKey: publicKey}})
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}
	_, otherPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(other): %v", err)
	}
	now := time.Now()

	tests := []struct {
		// name 表示测试用例名称。
		name string

		// claims 表示待签发的用户声明。
		claims *UserClaims

		// header 表示覆盖或删除的 JOSE 头。
		header map[string]any

		// method 表示测试令牌使用的签名算法。
		method jwt.SigningMethod

		// key 表示测试令牌使用的签名密钥。
		key any

		// expectedIssuer 表示验证时传入的预期签发方。
		expectedIssuer string

		// expectedAudience 表示验证时传入的预期受众。
		expectedAudience string
	}{
		{name: "missing typ", claims: validAsymmetricClaims(now), header: map[string]any{"typ": nil}},
		{name: "wrong typ", claims: validAsymmetricClaims(now), header: map[string]any{"typ": "at+jwt"}},
		{name: "missing kid", claims: validAsymmetricClaims(now), header: map[string]any{"kid": nil}},
		{name: "empty kid", claims: validAsymmetricClaims(now), header: map[string]any{"kid": ""}},
		{name: "unknown kid", claims: validAsymmetricClaims(now), header: map[string]any{"kid": "unknown"}},
		{name: "embedded jku", claims: validAsymmetricClaims(now), header: map[string]any{"jku": "https://attacker.example/jwks"}},
		{name: "embedded x5u", claims: validAsymmetricClaims(now), header: map[string]any{"x5u": "https://attacker.example/cert"}},
		{name: "alg none", claims: validAsymmetricClaims(now), method: jwt.SigningMethodNone, key: jwt.UnsafeAllowNoneSignatureType},
		{name: "HS256 confusion", claims: validAsymmetricClaims(now), method: jwt.SigningMethodHS256, key: []byte(publicKey)},
		{name: "wrong Ed25519 signature", claims: validAsymmetricClaims(now), key: otherPrivateKey},
		{name: "missing issuer", claims: mutateClaims(validAsymmetricClaims(now), func(c *UserClaims) { c.Issuer = "" })},
		{name: "wrong issuer", claims: validAsymmetricClaims(now), expectedIssuer: "https://other.example.com"},
		{name: "missing audience", claims: mutateClaims(validAsymmetricClaims(now), func(c *UserClaims) { c.RegisteredClaims.Audience = nil })},
		{name: "empty audience member", claims: mutateClaims(validAsymmetricClaims(now), func(c *UserClaims) {
			c.RegisteredClaims.Audience = jwt.ClaimStrings{testAudience, ""}
			c.AuthorizedParty = testAudience
		})},
		{name: "duplicate audience", claims: mutateClaims(validAsymmetricClaims(now), func(c *UserClaims) { c.RegisteredClaims.Audience = jwt.ClaimStrings{testAudience, testAudience} })},
		{name: "wrong audience", claims: validAsymmetricClaims(now), expectedAudience: "other-api"},
		{name: "missing subject", claims: mutateClaims(validAsymmetricClaims(now), func(c *UserClaims) { c.Subject = "" })},
		{name: "missing issued at", claims: mutateClaims(validAsymmetricClaims(now), func(c *UserClaims) { c.RegisteredClaims.IssuedAt = nil })},
		{name: "future issued at", claims: mutateClaims(validAsymmetricClaims(now), func(c *UserClaims) { c.RegisteredClaims.IssuedAt = jwt.NewNumericDate(now.Add(time.Hour)) })},
		{name: "future not before", claims: mutateClaims(validAsymmetricClaims(now), func(c *UserClaims) { c.NotBefore = jwt.NewNumericDate(now.Add(time.Hour)) })},
		{name: "missing expiration", claims: mutateClaims(validAsymmetricClaims(now), func(c *UserClaims) { c.RegisteredClaims.ExpiresAt = nil })},
		{name: "expired", claims: mutateClaims(validAsymmetricClaims(now), func(c *UserClaims) { c.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Hour)) })},
		{name: "missing jti", claims: mutateClaims(validAsymmetricClaims(now), func(c *UserClaims) { c.ID = "" })},
		{name: "multiple audiences missing azp", claims: mutateClaims(validAsymmetricClaims(now), func(c *UserClaims) { c.RegisteredClaims.Audience = jwt.ClaimStrings{testAudience, "account"} })},
		{name: "multiple audiences wrong azp", claims: mutateClaims(validAsymmetricClaims(now), func(c *UserClaims) {
			c.RegisteredClaims.Audience = jwt.ClaimStrings{testAudience, "account"}
			c.AuthorizedParty = "account"
		})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := tt.method
			if method == nil {
				method = jwt.SigningMethodEdDSA
			}
			key := tt.key
			if key == nil {
				key = privateKey
			}
			token := jwt.NewWithClaims(method, tt.claims)
			token.Header["typ"] = tokenTypeJWT
			token.Header["kid"] = "key-1"
			for name, value := range tt.header {
				if value == nil {
					delete(token.Header, name)
				} else {
					token.Header[name] = value
				}
			}
			raw, signErr := token.SignedString(key)
			if signErr != nil {
				t.Fatalf("SignedString: %v", signErr)
			}
			expectedIssuer := tt.expectedIssuer
			if expectedIssuer == "" {
				expectedIssuer = testIssuer
			}
			expectedAudience := tt.expectedAudience
			if expectedAudience == "" {
				expectedAudience = testAudience
			}
			if _, err := verifier.Verify(context.Background(), raw, expectedIssuer, expectedAudience); !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("Verify error = %v, want ErrInvalidCredential", err)
			}
		})
	}
}

func TestTokenVerifierAcceptsOptionalNBFAndValidAZP(t *testing.T) {
	signer, key, err := GenerateTokenSigner("key-1")
	if err != nil {
		t.Fatalf("GenerateTokenSigner: %v", err)
	}
	verifier, err := NewTokenVerifier([]VerificationKey{key})
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}

	tests := []struct {
		// name 表示测试用例名称。
		name string

		// claims 表示待签发的用户声明。
		claims *UserClaims
	}{
		{name: "nbf omitted", claims: validAsymmetricClaims(time.Now())},
		{name: "nbf in past", claims: mutateClaims(validAsymmetricClaims(time.Now()), func(c *UserClaims) { c.NotBefore = jwt.NewNumericDate(time.Now().Add(-time.Minute)) })},
		{name: "multiple audiences with azp", claims: mutateClaims(validAsymmetricClaims(time.Now()), func(c *UserClaims) {
			c.RegisteredClaims.Audience = jwt.ClaimStrings{testAudience, "account"}
			c.AuthorizedParty = testAudience
		})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, _, err := signer.Sign(context.Background(), tt.claims)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if _, err := verifier.Verify(context.Background(), raw, testIssuer, testAudience); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func TestAsymmetricKeyValidationAndContext(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	invalidKeys := []struct {
		// name 表示无效配置测试用例名称。
		name string

		// keys 表示待校验的验证密钥集合。
		keys []VerificationKey
	}{
		{name: "empty set"},
		{name: "empty kid", keys: []VerificationKey{{Algorithm: JWTAlgorithmEdDSA, PublicKey: publicKey}}},
		{name: "wrong algorithm", keys: []VerificationKey{{KeyID: "key", Algorithm: "HS256", PublicKey: publicKey}}},
		{name: "wrong key type", keys: []VerificationKey{{KeyID: "key", Algorithm: JWTAlgorithmEdDSA, PublicKey: []byte(publicKey)}}},
		{name: "short public key", keys: []VerificationKey{{KeyID: "key", Algorithm: JWTAlgorithmEdDSA, PublicKey: ed25519.PublicKey{1}}}},
		{name: "duplicate kid", keys: []VerificationKey{{KeyID: "key", Algorithm: JWTAlgorithmEdDSA, PublicKey: publicKey}, {KeyID: "key", Algorithm: JWTAlgorithmEdDSA, PublicKey: publicKey}}},
	}
	for _, tt := range invalidKeys {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewTokenVerifier(tt.keys); !errors.Is(err, ErrAuthBackendUnavailable) {
				t.Fatalf("NewTokenVerifier error = %v, want ErrAuthBackendUnavailable", err)
			}
		})
	}
	if _, err := NewTokenSigner("", privateKey); !errors.Is(err, ErrAuthBackendUnavailable) {
		t.Fatalf("NewTokenSigner empty kid error = %v, want ErrAuthBackendUnavailable", err)
	}
	if _, err := NewTokenSigner("key", ed25519.PrivateKey{1}); !errors.Is(err, ErrAuthBackendUnavailable) {
		t.Fatalf("NewTokenSigner short key error = %v, want ErrAuthBackendUnavailable", err)
	}
	inconsistentPrivateKey := append(ed25519.PrivateKey(nil), privateKey...)
	inconsistentPrivateKey[len(inconsistentPrivateKey)-1] ^= 1
	if _, err := NewTokenSigner("key", inconsistentPrivateKey); !errors.Is(err, ErrAuthBackendUnavailable) {
		t.Fatalf("NewTokenSigner inconsistent key error = %v, want ErrAuthBackendUnavailable", err)
	}

	signer, err := NewTokenSigner("key", privateKey)
	if err != nil {
		t.Fatalf("NewTokenSigner: %v", err)
	}
	verifier, err := NewTokenVerifier([]VerificationKey{signer.VerificationKey()})
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := signer.Sign(ctx, validAsymmetricClaims(time.Now())); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sign canceled error = %v, want context.Canceled", err)
	}
	if _, err := verifier.Verify(ctx, "token", testIssuer, testAudience); !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify canceled error = %v, want context.Canceled", err)
	}
}

func TestPublicJWKSDeterministicAndPublicOnly(t *testing.T) {
	firstSigner, firstKey, err := GenerateTokenSigner("z-last")
	if err != nil {
		t.Fatalf("GenerateTokenSigner(first): %v", err)
	}
	_, secondKey, err := GenerateTokenSigner("a-first")
	if err != nil {
		t.Fatalf("GenerateTokenSigner(second): %v", err)
	}
	verifier, err := NewTokenVerifier([]VerificationKey{firstKey, secondKey})
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}
	jwks, err := verifier.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(jwks.Keys) != 2 || jwks.Keys[0].KeyID != "a-first" || jwks.Keys[1].KeyID != "z-last" {
		t.Fatalf("JWKS order = %#v", jwks.Keys)
	}
	for _, key := range jwks.Keys {
		if key.KeyType != "OKP" || key.Curve != "Ed25519" || key.Algorithm != "EdDSA" || key.Use != "sig" {
			t.Fatalf("JWK metadata = %#v", key)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			t.Fatalf("JWK x = %q, decode error = %v", key.X, err)
		}
	}

	encoded, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	repeated, err := verifier.JWKS()
	if err != nil {
		t.Fatalf("JWKS repeated: %v", err)
	}
	repeatedEncoded, err := json.Marshal(repeated)
	if err != nil {
		t.Fatalf("Marshal repeated: %v", err)
	}
	if string(encoded) != string(repeatedEncoded) {
		t.Fatalf("JWKS is not deterministic:\n%s\n%s", encoded, repeatedEncoded)
	}
	if strings.Contains(string(encoded), base64.RawURLEncoding.EncodeToString(firstSigner.privateKey)) || strings.Contains(string(encoded), "private") || strings.Contains(string(encoded), `"d"`) {
		t.Fatalf("JWKS exposes private material: %s", encoded)
	}

	var document struct {
		// Keys 保存用于检查字段白名单的原始 JWK 对象。
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range document.Keys {
		if len(key) != 6 {
			t.Fatalf("JWK fields = %v, want exactly six public fields", key)
		}
		for _, name := range []string{"kty", "crv", "x", "kid", "alg", "use"} {
			if _, ok := key[name]; !ok {
				t.Fatalf("JWK missing %q: %v", name, key)
			}
		}
	}
}

func TestTokenVerifierRejectsMalformedTokens(t *testing.T) {
	_, key, err := GenerateTokenSigner("key")
	if err != nil {
		t.Fatalf("GenerateTokenSigner: %v", err)
	}
	verifier, err := NewTokenVerifier([]VerificationKey{key})
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}
	for _, raw := range []string{"", ".", "a.b.c", "a.b.c.d", "not-a-jwt", "eyJhbGciOiJFZERTQSJ9.e30."} {
		if _, err := verifier.Verify(context.Background(), raw, testIssuer, testAudience); !errors.Is(err, ErrInvalidCredential) {
			t.Errorf("Verify(%q) error = %v, want ErrInvalidCredential", raw, err)
		}
	}
}

func FuzzTokenVerifierMalformed(f *testing.F) {
	_, key, err := GenerateTokenSigner("fuzz-key")
	if err != nil {
		f.Fatalf("GenerateTokenSigner: %v", err)
	}
	verifier, err := NewTokenVerifier([]VerificationKey{key})
	if err != nil {
		f.Fatalf("NewTokenVerifier: %v", err)
	}
	for _, seed := range []string{"", ".", "a.b.c", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwia2lkIjoiZnV6ei1rZXkifQ.e30."} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = verifier.Verify(context.Background(), raw, testIssuer, testAudience)
	})
}

func validAsymmetricClaims(now time.Time) *UserClaims {
	return &UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    testIssuer,
			Subject:   "user-42",
			Audience:  jwt.ClaimStrings{testAudience},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
			ID:        "token-123",
		},
		UserID:          42,
		UIN:             84,
		CompanyID:       126,
		MembershipEpoch: 7,
		LoginWay:        LoginWayEmail,
	}
}

func mutateClaims(claims *UserClaims, mutate func(*UserClaims)) *UserClaims {
	mutate(claims)
	return claims
}

type fakeTokenSigner struct {
	// raw 保存测试替身返回的原始令牌。
	raw string

	// keyID 保存测试替身返回的密钥标识。
	keyID string
}

func (signer fakeTokenSigner) Sign(context.Context, jwt.Claims) (string, string, error) {
	return signer.raw, signer.keyID, nil
}

type fakeTokenVerifier struct {
	// claims 保存测试替身返回的声明。
	claims *UserClaims
}

func (verifier fakeTokenVerifier) Verify(context.Context, string, string, string) (*UserClaims, error) {
	return verifier.claims, nil
}

func validSignedPayload(now time.Time, prefix string) string {
	return fmt.Sprintf(
		`{%s"iss":%q,"sub":"user-42","aud":[%q],"exp":%d,"iat":%d,"jti":"token-123","c":42,"u":84,"o":126,"m":7,"l":2}`,
		prefix,
		testIssuer,
		testAudience,
		now.Add(time.Hour).Unix(),
		now.Add(-time.Minute).Unix(),
	)
}

func signRawEdDSA(t *testing.T, privateKey ed25519.PrivateKey, header, payload string) string {
	t.Helper()
	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(header))
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingInput := encodedHeader + "." + encodedPayload
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
