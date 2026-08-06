package auth

import (
	"fmt"
	"strings"
	"sync"
)

const minJWTSecretLength = 32

// JWTIssuerConfig defines the verification contract for tokens from an issuer.
type JWTIssuerConfig struct {
	Issuer   string
	Audience string
	Secret   string
}

type jwtIssuer struct {
	audience string
	secret   []byte
}

var (
	jwtIssuers   = map[string]jwtIssuer{}
	jwtIssuersMu sync.RWMutex
)

// RegisterJWTIssuer registers an HMAC-SHA256 token issuer.
func RegisterJWTIssuer(cfg JWTIssuerConfig) error {
	cfg.Issuer = strings.TrimSpace(cfg.Issuer)
	cfg.Audience = strings.TrimSpace(cfg.Audience)
	if cfg.Issuer == "" {
		return fmt.Errorf("jwt issuer is required")
	}
	if cfg.Audience == "" {
		return fmt.Errorf("jwt audience is required")
	}
	if len(cfg.Secret) < minJWTSecretLength {
		return fmt.Errorf("jwt secret must contain at least %d bytes", minJWTSecretLength)
	}

	jwtIssuersMu.Lock()
	jwtIssuers[cfg.Issuer] = jwtIssuer{
		audience: cfg.Audience,
		secret:   []byte(cfg.Secret),
	}
	jwtIssuersMu.Unlock()
	return nil
}

// RegisterJwtSecret registers an issuer using the issuer itself as audience.
// Deprecated: use RegisterJWTIssuer so registration errors are handled.
func RegisterJwtSecret(issuer string, secret string) error {
	return RegisterJWTIssuer(JWTIssuerConfig{
		Issuer:   issuer,
		Audience: issuer,
		Secret:   secret,
	})
}

// GetJwtSecret returns the key for an explicitly registered issuer.
func GetJwtSecret(issuer string) ([]byte, error) {
	registered, err := getJWTIssuer(issuer)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), registered.secret...), nil
}

// GetJWTVerification returns the key and expected audience for an issuer.
func GetJWTVerification(issuer string) ([]byte, string, error) {
	registered, err := getJWTIssuer(issuer)
	if err != nil {
		return nil, "", err
	}
	return registered.secret, registered.audience, nil
}

func getJWTIssuer(issuer string) (jwtIssuer, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return jwtIssuer{}, fmt.Errorf("jwt issuer is required")
	}

	jwtIssuersMu.RLock()
	registered, ok := jwtIssuers[issuer]
	jwtIssuersMu.RUnlock()
	if !ok {
		return jwtIssuer{}, fmt.Errorf("jwt issuer %q is not registered", issuer)
	}
	registered.secret = append([]byte(nil), registered.secret...)
	return registered, nil
}
