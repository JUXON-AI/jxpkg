package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
)

const (
	// InternalAuthorizedSessionResolvePath 是同时解析会话与组织授权的内部路径。
	InternalAuthorizedSessionResolvePath  = "/internal/session/authorize"
	maximumAuthorizedSessionResponseBytes = maximumAuthorizationResponseBytes + maximumSessionResolveResponseBytes
)

// AuthorizedSessionResolveRequest 仅包含受信任业务服务从当前路由和 Cookie 得到的输入。
type AuthorizedSessionResolveRequest struct {
	Host                 string           `json:"host"`
	Service              string           `json:"service"`
	SessionID            string           `json:"session_id"`
	IncludeAuthorization bool             `json:"include_authorization"`
	Permissions          []PermissionCode `json:"permissions"`
}

// AuthorizedSession 是同一次 Account 权威校验得到的主体和授权上下文。
type AuthorizedSession struct {
	Principal     SessionPrincipal
	Authorization AuthorizationContextResolveResponse
}

// AuthorizedSessionResolveResponse 是内部 mTLS 协议的响应格式。
type AuthorizedSessionResolveResponse struct {
	Session       SessionResolveResponse               `json:"session"`
	Authorization *AuthorizationContextResolveResponse `json:"authorization,omitempty"`
}

// AuthorizedSessionResolver 解析单次请求的会话和授权上下文。
type AuthorizedSessionResolver interface {
	ResolveAuthorized(context.Context, AuthorizedSessionResolveRequest) (*AuthorizedSession, error)
}

// DecodeAuthorizedSessionResolveRequest 严格拒绝未知字段、重复字段与无效权限。
func DecodeAuthorizedSessionResolveRequest(reader io.Reader) (AuthorizedSessionResolveRequest, error) {
	var request AuthorizedSessionResolveRequest
	if err := decodeResolverObject(reader, &request, "host", "service", "session_id", "include_authorization", "permissions"); err != nil {
		return AuthorizedSessionResolveRequest{}, err
	}
	if !validSessionResolveHost(request.Host) || !validSessionResolveIdentifier(request.Service) || !validOpaqueSessionID(request.SessionID) ||
		len(request.Permissions) > maximumAuthorizationPermissions || request.Permissions == nil || (!request.IncludeAuthorization && len(request.Permissions) != 0) {
		return AuthorizedSessionResolveRequest{}, ErrInvalidCredential
	}
	seen := make(map[PermissionCode]struct{}, len(request.Permissions))
	for _, permission := range request.Permissions {
		if !validPermissionCode(permission) {
			return AuthorizedSessionResolveRequest{}, ErrInvalidCredential
		}
		if _, exists := seen[permission]; exists {
			return AuthorizedSessionResolveRequest{}, ErrInvalidCredential
		}
		seen[permission] = struct{}{}
	}
	return request, nil
}

func sessionPrincipalFromWire(wire SessionResolveResponse, host string) (*SessionPrincipal, error) {
	csrfHash, err := base64.RawURLEncoding.Strict().DecodeString(wire.CSRFTokenHash)
	if err != nil || len(csrfHash) != sha256.Size || wire.UserID == 0 || wire.UIN == 0 || wire.CompanyID == 0 || wire.MembershipEpoch == 0 || wire.Host != host ||
		!validSessionResolveIdentifier(wire.ClientID) || wire.SessionVersion == 0 || wire.AuthenticatedAt <= 0 || wire.IdleExpiresAt <= 0 || wire.AbsoluteExpiresAt <= 0 ||
		wire.AuthenticatedAt > wire.IdleExpiresAt || wire.IdleExpiresAt > wire.AbsoluteExpiresAt {
		return nil, fmt.Errorf("%w: invalid session resolve principal", ErrAuthBackendUnavailable)
	}
	return &SessionPrincipal{
		Claims: UserClaims{UserID: wire.UserID, UIN: wire.UIN, CompanyID: wire.CompanyID, MembershipEpoch: wire.MembershipEpoch},
		Host:   wire.Host, ClientID: wire.ClientID, SessionVersion: wire.SessionVersion,
		AuthenticatedAt: wire.AuthenticatedAt, IdleExpiresAt: wire.IdleExpiresAt, AbsoluteExpiresAt: wire.AbsoluteExpiresAt,
		CSRFTokenHash: csrfHash,
	}, nil
}

// ResolveAuthorized 通过同一条 mTLS 请求取得 Account 会话及授权快照。
func (client *InternalSessionResolverClient) ResolveAuthorized(ctx context.Context, request AuthorizedSessionResolveRequest) (*AuthorizedSession, error) {
	if client == nil || client.client == nil || client.authorizedSessionEndpoint == "" {
		return nil, fmt.Errorf("%w: authorized session resolver is not configured", ErrAuthBackendUnavailable)
	}
	if request.Service != client.service {
		return nil, ErrInvalidCredential
	}
	request.Service = client.service
	request.Permissions = append([]PermissionCode{}, request.Permissions...)
	if !validSessionResolveHost(request.Host) || !validOpaqueSessionID(request.SessionID) || len(request.Permissions) > maximumAuthorizationPermissions || (!request.IncludeAuthorization && len(request.Permissions) != 0) {
		return nil, ErrInvalidCredential
	}
	seen := make(map[PermissionCode]struct{}, len(request.Permissions))
	for _, permission := range request.Permissions {
		if !validPermissionCode(permission) {
			return nil, ErrInvalidCredential
		}
		if _, exists := seen[permission]; exists {
			return nil, ErrInvalidCredential
		}
		seen[permission] = struct{}{}
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%w: encode authorized session request", ErrAuthBackendUnavailable)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.authorizedSessionEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: create authorized session request", ErrAuthBackendUnavailable)
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Cache-Control", "no-store")
	response, err := client.client.Do(httpRequest)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrAuthBackendUnavailable, ctxErr)
		}
		return nil, fmt.Errorf("%w: authorized session transport", ErrAuthBackendUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusNotFound {
		return nil, ErrInvalidCredential
	}
	if response.StatusCode == http.StatusForbidden {
		return nil, ErrAuthorizationDenied
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: authorized session returned status %d", ErrAuthBackendUnavailable, response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || response.ContentLength > maximumAuthorizedSessionResponseBytes {
		return nil, fmt.Errorf("%w: invalid authorized session response metadata", ErrAuthBackendUnavailable)
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, maximumAuthorizedSessionResponseBytes+1))
	if err != nil || len(document) > maximumAuthorizedSessionResponseBytes || validateJSONObject(document) != nil {
		return nil, fmt.Errorf("%w: invalid authorized session response", ErrAuthBackendUnavailable)
	}
	var wire AuthorizedSessionResolveResponse
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return nil, fmt.Errorf("%w: decode authorized session response", ErrAuthBackendUnavailable)
	}
	principal, err := sessionPrincipalFromWire(wire.Session, request.Host)
	if err != nil {
		return nil, err
	}
	result := &AuthorizedSession{Principal: *principal}
	if request.IncludeAuthorization {
		authorizationRequest := AuthorizationContextResolveRequest{Service: request.Service, CompanyID: principal.Claims.CompanyID, UIN: principal.Claims.UIN,
			MembershipEpoch: principal.Claims.MembershipEpoch, Permissions: request.Permissions}
		if wire.Authorization == nil || !validAuthorizationResponse(authorizationRequest, *wire.Authorization) {
			return nil, fmt.Errorf("%w: invalid authorized session context", ErrAuthBackendUnavailable)
		}
		result.Authorization = *wire.Authorization
	} else if wire.Authorization != nil {
		return nil, fmt.Errorf("%w: unexpected authorization context", ErrAuthBackendUnavailable)
	}
	return result, nil
}

var _ AuthorizedSessionResolver = (*InternalSessionResolverClient)(nil)
