package middleware

import (
	"errors"

	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
)

// AuthorizationUnavailable reports whether a failed authorization check came from an unavailable authority.
func AuthorizationUnavailable(err error) bool {
	return err != nil && !errors.Is(err, auth.ErrAuthorizationDenied)
}
