package auth

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestBrowserSessionMetadataIsImmutable(t *testing.T) {
	hash := sha256.Sum256([]byte("csrf-token"))
	wantHash := append([]byte(nil), hash[:]...)
	principal := SessionPrincipal{
		Host:              "app.example.com",
		ClientID:          "web-client",
		SessionVersion:    7,
		AuthenticatedAt:   100,
		IdleExpiresAt:     200,
		AbsoluteExpiresAt: 300,
		CSRFTokenHash:     hash[:],
	}

	status := NewBrowserSessionLoginStatus(principal)
	principal.CSRFTokenHash[0] ^= 0xff
	if status.BrowserSessionExpiresAt() != 200 {
		t.Fatalf("BrowserSessionExpiresAt() = %d, want 200", status.BrowserSessionExpiresAt())
	}
	if !status.MatchesBrowserCSRF("csrf-token") || bytes.Equal(principal.CSRFTokenHash, wantHash) {
		t.Fatal("CSRF hash changed through an external slice")
	}
}
