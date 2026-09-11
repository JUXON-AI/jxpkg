package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

// ErrCompanyIdentityNotFound means the authoritative directory has no available company.
// Providers map it to the existing internal HTTP 404 response.
var ErrCompanyIdentityNotFound = errors.New("company identity not found")

// DecodeSessionResolveRequest enforces the fixed resolver JSON request contract.
// Duplicate, unknown, missing, null and trailing values are rejected before use.
func DecodeSessionResolveRequest(reader io.Reader) (SessionResolveRequest, error) {
	var request SessionResolveRequest
	if err := decodeResolverObject(reader, &request, "host", "service", "session_id"); err != nil {
		return request, err
	}
	sessionID, err := base64.RawURLEncoding.Strict().DecodeString(request.SessionID)
	if !validSessionResolveIdentifier(request.Service) || err != nil || len(sessionID) != 32 || base64.RawURLEncoding.EncodeToString(sessionID) != request.SessionID || request.Host == "" {
		return SessionResolveRequest{}, ErrInvalidCredential
	}
	return request, nil
}

// DecodeCompanyIdentityResolveRequest enforces the bounded company directory contract.
func DecodeCompanyIdentityResolveRequest(reader io.Reader) (CompanyIdentityResolveRequest, error) {
	var request CompanyIdentityResolveRequest
	if err := decodeResolverObject(reader, &request, "service", "company_id", "uins"); err != nil {
		return request, err
	}
	if !validSessionResolveIdentifier(request.Service) || request.CompanyID == 0 || len(request.UINs) == 0 || len(request.UINs) > maximumCompanyIdentityCount {
		return CompanyIdentityResolveRequest{}, ErrInvalidCredential
	}
	seen := make(map[uint]struct{}, len(request.UINs))
	for _, uin := range request.UINs {
		if _, duplicate := seen[uin]; duplicate || uin == 0 {
			return CompanyIdentityResolveRequest{}, ErrInvalidCredential
		}
		seen[uin] = struct{}{}
	}
	return request, nil
}

func decodeResolverObject(reader io.Reader, output any, required ...string) error {
	const maximumRequestBytes = 8 * 1024
	document, err := io.ReadAll(io.LimitReader(reader, maximumRequestBytes+1))
	if err != nil || len(document) > maximumRequestBytes || validateJSONObject(document) != nil {
		return ErrInvalidCredential
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(document, &members) != nil || len(members) != len(required) {
		return ErrInvalidCredential
	}
	for _, key := range required {
		value, exists := members[key]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrInvalidCredential
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(output) != nil {
		return ErrInvalidCredential
	}
	return nil
}
