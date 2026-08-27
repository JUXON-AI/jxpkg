package middleware

import (
	"errors"
	"testing"

	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
)

func TestBearerToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{name: "bearer", header: "Bearer token", want: "token"},
		{name: "case insensitive", header: "bearer token", want: "token"},
		{name: "missing scheme", header: "token"},
		{name: "wrong scheme", header: "Basic token"},
		{name: "missing token", header: "Bearer"},
		{name: "extra value", header: "Bearer token extra"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := bearerToken(tt.header)
			if tt.want == "" {
				if !errors.Is(err, auth.ErrInvalidCredential) {
					t.Fatalf("bearerToken error = %v, want ErrInvalidCredential", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("bearerToken: %v", err)
			}
			if got != tt.want {
				t.Fatalf("bearerToken = %q, want %q", got, tt.want)
			}
		})
	}
}
