package auth

import (
	"strings"
	"testing"
)

func TestRegisterJWTIssuerValidatesConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  JWTIssuerConfig
	}{
		{name: "missing issuer", cfg: JWTIssuerConfig{Audience: "web", Secret: strings.Repeat("a", 32)}},
		{name: "missing audience", cfg: JWTIssuerConfig{Issuer: "account", Secret: strings.Repeat("a", 32)}},
		{name: "short secret", cfg: JWTIssuerConfig{Issuer: "account", Audience: "web", Secret: "short"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := RegisterJWTIssuer(tt.cfg); err == nil {
				t.Fatal("expected invalid JWT issuer configuration to fail")
			}
		})
	}
}

func TestRegisterJWTIssuerStoresVerificationContract(t *testing.T) {
	issuer := "jwt-test-registered"
	audience := "jxone-web"
	secret := strings.Repeat("b", 32)

	if err := RegisterJWTIssuer(JWTIssuerConfig{
		Issuer:   issuer,
		Audience: audience,
		Secret:   secret,
	}); err != nil {
		t.Fatalf("register JWT issuer: %v", err)
	}

	key, gotAudience, err := GetJWTVerification(issuer)
	if err != nil {
		t.Fatalf("get JWT verification: %v", err)
	}
	if string(key) != secret {
		t.Fatalf("unexpected key: %q", string(key))
	}
	if gotAudience != audience {
		t.Fatalf("unexpected audience: %q", gotAudience)
	}

	key[0] = 'x'
	keyAgain, err := GetJwtSecret(issuer)
	if err != nil {
		t.Fatalf("get JWT secret: %v", err)
	}
	if string(keyAgain) != secret {
		t.Fatal("caller mutation changed the registered JWT key")
	}
}

func TestGetJWTVerificationRejectsUnknownIssuer(t *testing.T) {
	t.Parallel()

	if _, _, err := GetJWTVerification("jwt-test-unknown"); err == nil {
		t.Fatal("expected unknown issuer to be rejected")
	}
}

func TestRegisterJwtSecretReturnsValidationError(t *testing.T) {
	t.Parallel()

	if err := RegisterJwtSecret("legacy-test", "short"); err == nil {
		t.Fatal("expected legacy registration helper to expose validation errors")
	}
}
