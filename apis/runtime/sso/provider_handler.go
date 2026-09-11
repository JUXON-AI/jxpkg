package sso

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"

	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
)

// ServeHTTP implements the fixed internal resolver protocol without opening a listener.
// Even direct callers must supply a verified TLS peer; forwarded identity is rejected.
func (provider *Provider) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if provider == nil || provider.sessions == nil || provider.identities == nil {
		providerError(writer, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	if request.Method != http.MethodPost || (request.URL.Path != auth.InternalSessionResolvePath && request.URL.Path != auth.InternalCompanyIdentityResolvePath) || request.URL.RawPath != "" || request.URL.RawQuery != "" {
		providerError(writer, http.StatusNotFound, "not_found")
		return
	}
	for _, header := range []string{"Authorization", "Cookie", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Original-URL", "X-Rewrite-URL"} {
		if len(request.Header.Values(header)) != 0 {
			providerError(writer, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	caller, ok := provider.caller(request)
	if !ok {
		providerError(writer, http.StatusForbidden, "invalid_caller")
		return
	}
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		providerError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" || request.ContentLength > 8*1024 {
		providerError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 8*1024)
	defer request.Body.Close()
	if request.URL.Path == auth.InternalCompanyIdentityResolvePath {
		provider.resolveIdentities(writer, request, caller)
		return
	}
	provider.resolveSession(writer, request, caller)
}

func (provider *Provider) caller(request *http.Request) (providerCaller, bool) {
	if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return providerCaller{}, false
	}
	leaf := request.TLS.VerifiedChains[0][0]
	if leaf == nil || len(leaf.URIs) != 1 || leaf.URIs[0] == nil {
		return providerCaller{}, false
	}
	principal := leaf.URIs[0].String()
	if !validProviderPrincipal(principal) {
		return providerCaller{}, false
	}
	caller, ok := provider.callers[principal]
	return caller, ok
}

func (provider *Provider) resolveSession(writer http.ResponseWriter, request *http.Request, caller providerCaller) {
	input, err := auth.DecodeSessionResolveRequest(request.Body)
	if err != nil || input.Service != caller.Service {
		providerError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	allowed := false
	for _, host := range caller.AllowedHosts {
		if input.Host == host {
			allowed = true
			break
		}
	}
	if !allowed {
		providerError(writer, http.StatusUnauthorized, "invalid_session")
		return
	}
	principal, err := provider.sessions.Resolve(request.Context(), input)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredential) || errors.Is(err, auth.ErrInvalidPrincipal) {
			providerError(writer, http.StatusUnauthorized, "invalid_session")
		} else {
			providerError(writer, http.StatusServiceUnavailable, "temporarily_unavailable")
		}
		return
	}
	if !validProviderSession(principal, input.Host) {
		providerError(writer, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	response := auth.SessionResolveResponse{
		UserID: principal.Claims.UserID, UIN: principal.Claims.UIN, CompanyID: principal.Claims.CompanyID, MembershipEpoch: principal.Claims.MembershipEpoch,
		Host: principal.Host, ClientID: principal.ClientID, SessionVersion: principal.SessionVersion,
		AuthenticatedAt: principal.AuthenticatedAt, IdleExpiresAt: principal.IdleExpiresAt, AbsoluteExpiresAt: principal.AbsoluteExpiresAt,
		CSRFTokenHash: base64.RawURLEncoding.EncodeToString(principal.CSRFTokenHash),
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(response)
}

func validProviderSession(principal *auth.SessionPrincipal, host string) bool {
	return principal != nil && principal.Host == host && validProviderIdentifier(principal.ClientID) &&
		principal.Claims.UserID != 0 && principal.Claims.UIN != 0 && principal.Claims.CompanyID != 0 && principal.Claims.MembershipEpoch != 0 &&
		principal.SessionVersion != 0 && principal.AuthenticatedAt > 0 && principal.AuthenticatedAt <= principal.IdleExpiresAt &&
		principal.IdleExpiresAt <= principal.AbsoluteExpiresAt && len(principal.CSRFTokenHash) == sha256.Size
}

func (provider *Provider) resolveIdentities(writer http.ResponseWriter, request *http.Request, caller providerCaller) {
	input, err := auth.DecodeCompanyIdentityResolveRequest(request.Body)
	if err != nil || input.Service != caller.Service {
		providerError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	identities, err := provider.identities.ResolveCompanyIdentities(request.Context(), input)
	if err != nil {
		if errors.Is(err, auth.ErrCompanyIdentityNotFound) {
			providerError(writer, http.StatusNotFound, "not_found")
		} else {
			providerError(writer, http.StatusServiceUnavailable, "temporarily_unavailable")
		}
		return
	}
	requested := make(map[uint]bool, len(input.UINs))
	for _, uin := range input.UINs {
		requested[uin] = true
	}
	for _, identity := range identities {
		if !requested[identity.UIN] || identity.MembershipEpoch == 0 || !validProviderIdentity(identity) {
			providerError(writer, http.StatusServiceUnavailable, "temporarily_unavailable")
			return
		}
		delete(requested, identity.UIN)
	}
	if identities == nil {
		identities = []auth.CompanyIdentity{}
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(auth.CompanyIdentityResolveResponse{CompanyID: input.CompanyID, Identities: identities})
}

func validProviderIdentity(identity auth.CompanyIdentity) bool {
	status := identity.Status
	return (status == auth.CompanyIdentityStatusActive || status == auth.CompanyIdentityStatusPending || status == auth.CompanyIdentityStatusDisabled || status == auth.CompanyIdentityStatusLeft) && (!identity.IsCompanyOwner || status == auth.CompanyIdentityStatusActive)
}

func providerError(writer http.ResponseWriter, status int, code string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = fmt.Fprintf(writer, "{\"error\":%q}\n", code)
}
