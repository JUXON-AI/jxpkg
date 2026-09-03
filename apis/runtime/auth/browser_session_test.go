package auth

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestSessionMetadataIsImmutable(t *testing.T) {
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

	metadata := NewSessionMetadata(principal)
	principal.CSRFTokenHash[0] ^= 0xff
	gotHash := metadata.CSRFTokenHash()
	gotHash[1] ^= 0xff

	if metadata.Host() != "app.example.com" || metadata.ClientID() != "web-client" {
		t.Fatalf("metadata identity = %q/%q", metadata.Host(), metadata.ClientID())
	}
	if metadata.SessionVersion() != 7 || metadata.AuthenticatedAt() != 100 ||
		metadata.IdleExpiresAt() != 200 || metadata.AbsoluteExpiresAt() != 300 {
		t.Fatalf("metadata timestamps/version were not preserved")
	}
	if !bytes.Equal(metadata.CSRFTokenHash(), wantHash) {
		t.Fatal("CSRF hash changed through an external slice")
	}
}
