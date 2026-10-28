package auth

import "errors"

var (
	// ErrInvalidCredential reports malformed or untrusted authentication material.
	ErrInvalidCredential = errors.New("invalid credential")

	// ErrAuthBackendUnavailable reports an unavailable authentication dependency.
	ErrAuthBackendUnavailable = errors.New("auth backend unavailable")

	// ErrAuthorizationDenied reports an authenticated caller without the requested permission.
	ErrAuthorizationDenied = errors.New("authorization denied")
)
