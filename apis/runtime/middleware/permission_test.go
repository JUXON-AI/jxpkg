package middleware

import (
	"errors"
	"testing"

	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
)

func TestAuthorizationUnavailableDistinguishesDenialFromDependencyFailure(t *testing.T) {
	tests := []struct {
		// name is the test case label.
		name string
		// err is the authorization failure under test.
		err error
		// want is whether callers should map the failure to an unavailable dependency.
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "denied", err: auth.ErrAuthorizationDenied, want: false},
		{name: "dependency failure", err: errors.New("directory unavailable"), want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := AuthorizationUnavailable(test.err); got != test.want {
				t.Fatalf("AuthorizationUnavailable() = %v, want %v", got, test.want)
			}
		})
	}
}
