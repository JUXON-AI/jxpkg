package middleware

import (
	"context"
	"errors"
	"testing"

	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
)

type browserSecurityResolver func(context.Context, auth.SessionResolveRequest) (*auth.SessionPrincipal, error)

func (resolver browserSecurityResolver) Resolve(ctx context.Context, request auth.SessionResolveRequest) (*auth.SessionPrincipal, error) {
	return resolver(ctx, request)
}

func TestNewBrowserSecurity(t *testing.T) {
	security, err := NewBrowserSecurity(BrowserSessionOptions{
		Service:      "service",
		CookieName:   "__Host-service_session",
		AllowedHosts: map[string]struct{}{"service.example.com": {}},
		Resolver: browserSecurityResolver(func(context.Context, auth.SessionResolveRequest) (*auth.SessionPrincipal, error) {
			return nil, errors.New("not called while constructing middleware")
		}),
	})
	if err != nil {
		t.Fatalf("NewBrowserSecurity() error = %v", err)
	}
	if security.CookieName() != "__Host-service_session" {
		t.Fatalf("CookieName() = %q", security.CookieName())
	}
	session, csrf := security.Handlers()
	if session == nil || csrf == nil {
		t.Fatal("Handlers() returned nil middleware")
	}
}

func TestNewBrowserSecurityRejectsInvalidOptions(t *testing.T) {
	if security, err := NewBrowserSecurity(BrowserSessionOptions{}); !errors.Is(err, auth.ErrAuthBackendUnavailable) || security != nil {
		t.Fatalf("NewBrowserSecurity() = %#v, %v", security, err)
	}
}
