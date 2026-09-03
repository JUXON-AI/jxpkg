package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.yaml.in/yaml/v3"
)

func TestParseToken(t *testing.T) {
	secret := "test-secret"
	setJWTConfig(JWTConfig{Secret: secret, Expire: time.Hour})
	t.Cleanup(func() { setJWTConfig(JWTConfig{}) })

	now := time.Now()
	tests := []struct {
		name   string
		method jwt.SigningMethod
		claims UserClaims
		wantID uint

		// wantMembershipEpoch 表示解析成功后预期的成员身份代次。
		wantMembershipEpoch uint64
	}{
		{
			name:   "legacy token without membership epoch",
			method: jwt.SigningMethodHS256,
			claims: UserClaims{UserID: 42, UIN: 84, CompanyID: 126, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix()},
			wantID: 42,
		},
		{
			name:   "legacy short times take precedence over standard claims",
			method: jwt.SigningMethodHS256,
			claims: UserClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					IssuedAt:  jwt.NewNumericDate(now.Add(time.Hour)),
					ExpiresAt: jwt.NewNumericDate(now.Add(-time.Hour)),
				},
				UserID: 42, CompanyID: 126, UIN: 84,
				IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
			},
			wantID: 42,
		},
		{
			name:   "wrong signing method",
			method: jwt.SigningMethodHS384,
			claims: UserClaims{UserID: 42, UIN: 84, CompanyID: 126, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix()},
		},
		{
			name:   "expired",
			method: jwt.SigningMethodHS256,
			claims: UserClaims{UserID: 42, UIN: 84, CompanyID: 126, IssuedAt: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(-time.Minute).Unix()},
		},
		{
			name:   "future issued at",
			method: jwt.SigningMethodHS256,
			claims: UserClaims{UserID: 42, UIN: 84, CompanyID: 126, IssuedAt: now.Add(time.Hour).Unix(), ExpiresAt: now.Add(2 * time.Hour).Unix()},
		},
		{
			name:   "missing user id",
			method: jwt.SigningMethodHS256,
			claims: UserClaims{UIN: 84, CompanyID: 126, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix()},
		},
		{
			name:   "missing UIN",
			method: jwt.SigningMethodHS256,
			claims: UserClaims{UserID: 42, CompanyID: 126, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix()},
		},
		{
			name:   "missing company",
			method: jwt.SigningMethodHS256,
			claims: UserClaims{UserID: 42, UIN: 84, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix()},
		},
		{
			name:   "missing issued at",
			method: jwt.SigningMethodHS256,
			claims: UserClaims{UserID: 42, UIN: 84, CompanyID: 126, ExpiresAt: now.Add(time.Hour).Unix()},
		},
		{
			name:   "missing expiration",
			method: jwt.SigningMethodHS256,
			claims: UserClaims{UserID: 42, UIN: 84, CompanyID: 126, IssuedAt: now.Add(-time.Minute).Unix()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawToken, err := jwt.NewWithClaims(tt.method, &tt.claims).SignedString([]byte(secret))
			if err != nil {
				t.Fatalf("sign token: %v", err)
			}

			claims, err := ParseToken(rawToken)
			if tt.wantID == 0 {
				if !errors.Is(err, ErrInvalidCredential) {
					t.Fatalf("ParseToken error = %v, want ErrInvalidCredential", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseToken: %v", err)
			}
			if claims.UserID != tt.wantID {
				t.Fatalf("UserID = %d, want %d", claims.UserID, tt.wantID)
			}
			if claims.MembershipEpoch != tt.wantMembershipEpoch {
				t.Fatalf("MembershipEpoch = %d, want %d", claims.MembershipEpoch, tt.wantMembershipEpoch)
			}
		})
	}
}

func TestParseTokenRequiresLoadedSecret(t *testing.T) {
	setJWTConfig(JWTConfig{})
	_, err := ParseToken("token")
	if !errors.Is(err, ErrAuthBackendUnavailable) {
		t.Fatalf("ParseToken error = %v, want ErrAuthBackendUnavailable", err)
	}
}

func TestIssueIdentityToken(t *testing.T) {
	setJWTConfig(JWTConfig{Secret: "test-secret", Expire: time.Hour})
	t.Cleanup(func() { setJWTConfig(JWTConfig{}) })

	rawToken, _, err := IssueIdentityToken(42, 84, 126, 7, LoginWayEmail)
	if err != nil {
		t.Fatalf("IssueIdentityToken: %v", err)
	}
	claims, err := ParseToken(rawToken)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if claims.UserID != 42 || claims.UIN != 84 || claims.CompanyID != 126 || claims.MembershipEpoch != 7 {
		t.Fatalf("claims = %+v, want user 42, UIN 84, company 126, membership epoch 7", claims)
	}
}

func TestIssueIdentityTokenRequiresIdentity(t *testing.T) {
	setJWTConfig(JWTConfig{Secret: "test-secret", Expire: time.Hour})
	t.Cleanup(func() { setJWTConfig(JWTConfig{}) })

	for _, input := range []struct {
		name      string
		uin       uint
		companyID uint
	}{
		{name: "missing UIN", companyID: 126},
		{name: "missing company", uin: 84},
	} {
		t.Run(input.name, func(t *testing.T) {
			_, _, err := IssueIdentityToken(42, input.uin, input.companyID, 0, LoginWayEmail)
			if !errors.Is(err, ErrInvalidPrincipal) {
				t.Fatalf("IssueIdentityToken error = %v, want ErrInvalidPrincipal", err)
			}
		})
	}
}

func TestIssueIdentityTokenRequiresConfig(t *testing.T) {
	setJWTConfig(JWTConfig{})
	_, _, err := IssueIdentityToken(42, 84, 126, 0, LoginWayEmail)
	if !errors.Is(err, ErrAuthBackendUnavailable) {
		t.Fatalf("IssueIdentityToken error = %v, want ErrAuthBackendUnavailable", err)
	}
}

func TestJWTConfigYAML(t *testing.T) {
	config := JWTConfig{}
	if err := yaml.Unmarshal([]byte("secret: test-secret\nexpire: 720h\n"), &config); err != nil {
		t.Fatalf("unmarshal JWT config: %v", err)
	}
	if config.Secret != "test-secret" {
		t.Fatalf("Secret = %q, want test-secret", config.Secret)
	}
	if config.Expire != 720*time.Hour {
		t.Fatalf("Expire = %s, want 720h", config.Expire)
	}
}

func TestValidateJWTConfig(t *testing.T) {
	tests := []struct {
		name   string
		config JWTConfig
		wantOK bool
	}{
		{name: "valid", config: JWTConfig{Secret: strings.Repeat("s", minimumJWTSecretBytes), Expire: time.Hour}, wantOK: true},
		{name: "empty secret", config: JWTConfig{Expire: time.Hour}},
		{name: "short secret", config: JWTConfig{Secret: strings.Repeat("s", minimumJWTSecretBytes-1), Expire: time.Hour}},
		{name: "invalid expiration", config: JWTConfig{Secret: strings.Repeat("s", minimumJWTSecretBytes)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateJWTConfig(tt.config)
			if tt.wantOK && err != nil {
				t.Fatalf("validateJWTConfig: %v", err)
			}
			if !tt.wantOK && !errors.Is(err, ErrAuthBackendUnavailable) {
				t.Fatalf("validateJWTConfig error = %v, want ErrAuthBackendUnavailable", err)
			}
		})
	}
}
