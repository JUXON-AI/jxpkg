package middleware

import (
	"fmt"

	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
)

// BrowserSecurity is the immutable middleware pair required by browser-session
// business routes. Session resolution must run before CSRF validation.
type BrowserSecurity struct {
	cookieName string
	session    gin.HandlerFunc
	csrf       gin.HandlerFunc
}

// NewBrowserSecurity validates one browser-session configuration and creates
// its ordered Session and CSRF middleware pair.
func NewBrowserSecurity(options BrowserSessionOptions) (*BrowserSecurity, error) {
	session, err := NewBrowserSessionMiddleware(options)
	if err != nil {
		return nil, err
	}
	csrf, err := NewCSRFMiddleware(options)
	if err != nil {
		return nil, err
	}
	if session == nil || csrf == nil {
		return nil, fmt.Errorf("%w: browser security middleware is unavailable", auth.ErrAuthBackendUnavailable)
	}
	return &BrowserSecurity{cookieName: options.CookieName, session: session, csrf: csrf}, nil
}

// CookieName returns the browser Session Cookie name that Bearer-only routes
// must reject.
func (security *BrowserSecurity) CookieName() string {
	if security == nil {
		return ""
	}
	return security.cookieName
}

// Handlers returns the Session and CSRF middleware in the required order.
func (security *BrowserSecurity) Handlers() (gin.HandlerFunc, gin.HandlerFunc) {
	if security == nil {
		return nil, nil
	}
	return security.session, security.csrf
}
