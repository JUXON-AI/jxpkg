package auth

import "github.com/golang-jwt/jwt/v5"

// UserClaims is the generic claims envelope accepted by the EdDSA verifier.
// Identity and authorization values remain in standard claims such as Sub.
type UserClaims struct {
	// RegisteredClaims contains the required issuer, audience, subject, time and token ID claims.
	jwt.RegisteredClaims

	// AuthorizedParty binds a multi-audience token to its authorized client.
	AuthorizedParty string `json:"azp,omitempty"`
}
