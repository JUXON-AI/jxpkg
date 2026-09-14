package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
)

const (
	// InternalAuthorizationContextResolvePath 是 Account 内部授权上下文解析接口的固定路径。
	InternalAuthorizationContextResolvePath = "/internal/authorization-context/resolve"

	maximumAuthorizationPermissions   = 32
	maximumAuthorizationDepartments   = 256
	maximumAuthorizationResponseBytes = 128 * 1024
)

var (
	// ErrAuthorizationDenied 表示当前公司身份不存在、失效或没有请求的权限。
	ErrAuthorizationDenied = errors.New("authorization denied")
)

// PermissionCode 表示跨服务鉴权协议中的不透明权限编码。
// 具体编码及其业务含义由权限所属服务维护。
type PermissionCode string

// AuthorizationDepartment 表示当前身份直接所属的一个有效部门。
type AuthorizationDepartment struct {
	// ID 表示部门标识。
	ID uint `json:"id"`

	// Path 表示由 Account 维护的部门物化路径。
	Path string `json:"path"`
}

// AuthorizationContextResolveRequest 描述业务服务解析授权上下文所需的输入。
type AuthorizationContextResolveRequest struct {
	// Service 表示调用方在 Account 工作负载注册表中的静态服务标识。
	Service string `json:"service"`

	// CompanyID 表示当前认证主体所在公司。
	CompanyID uint `json:"company_id"`

	// UIN 表示当前认证主体的公司身份标识。
	UIN uint `json:"uin"`

	// MembershipEpoch 表示浏览器会话携带的成员身份代次。
	MembershipEpoch uint64 `json:"membership_epoch"`

	// Permissions 表示本次请求需要判断的去重权限编码。
	Permissions []PermissionCode `json:"permissions"`
}

// AuthorizationContextResolveResponse 表示 Account 返回的权威授权上下文。
type AuthorizationContextResolveResponse struct {
	// CompanyID 表示上下文所属公司。
	CompanyID uint `json:"company_id"`

	// UIN 表示上下文所属公司身份。
	UIN uint `json:"uin"`

	// MembershipEpoch 表示 Account 当前确认的成员身份代次。
	MembershipEpoch uint64 `json:"membership_epoch"`

	// IsCompanyOwner 表示该身份是否为公司当前所有者。
	IsCompanyOwner bool `json:"is_company_owner"`

	// Departments 表示该身份直接所属的有效部门。
	Departments []AuthorizationDepartment `json:"departments"`

	// AllowedPermissions 表示请求权限中当前有效的子集。
	AllowedPermissions []PermissionCode `json:"allowed_permissions"`
}

// Allows 判断 Account 是否在本次权威上下文中允许指定平台权限。
func (response *AuthorizationContextResolveResponse) Allows(permission PermissionCode) bool {
	if response == nil {
		return false
	}
	for _, allowed := range response.AllowedPermissions {
		if allowed == permission {
			return true
		}
	}
	return false
}

// AuthorizationContextResolver 解析已认证公司身份的权威权限和部门上下文。
type AuthorizationContextResolver interface {
	ResolveAuthorizationContext(context.Context, AuthorizationContextResolveRequest) (*AuthorizationContextResolveResponse, error)
}

var _ AuthorizationContextResolver = (*InternalSessionResolverClient)(nil)

// ResolveAuthorizationContext 使用与 Session Resolve 相同的 mTLS 客户端读取授权上下文。
func (client *InternalSessionResolverClient) ResolveAuthorizationContext(
	ctx context.Context, request AuthorizationContextResolveRequest,
) (*AuthorizationContextResolveResponse, error) {
	if client == nil || client.client == nil || client.authorizationEndpoint == "" {
		return nil, fmt.Errorf("%w: authorization resolver client is not configured", ErrAuthBackendUnavailable)
	}
	request.Service = client.service
	if err := validateAuthorizationRequest(request); err != nil {
		return nil, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%w: encode authorization request", ErrAuthBackendUnavailable)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.authorizationEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: create authorization request", ErrAuthBackendUnavailable)
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Cache-Control", "no-store")

	response, err := client.client.Do(httpRequest)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrAuthBackendUnavailable, ctxErr)
		}
		return nil, fmt.Errorf("%w: authorization resolve transport", ErrAuthBackendUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound {
		return nil, ErrAuthorizationDenied
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: authorization resolve returned status %d", ErrAuthBackendUnavailable, response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || response.ContentLength > maximumAuthorizationResponseBytes {
		return nil, fmt.Errorf("%w: invalid authorization response metadata", ErrAuthBackendUnavailable)
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, maximumAuthorizationResponseBytes+1))
	if err != nil || len(document) > maximumAuthorizationResponseBytes || validateJSONObject(document) != nil {
		return nil, fmt.Errorf("%w: invalid authorization response", ErrAuthBackendUnavailable)
	}
	var result AuthorizationContextResolveResponse
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || !validAuthorizationResponse(request, result) {
		return nil, fmt.Errorf("%w: decode authorization response", ErrAuthBackendUnavailable)
	}
	return &result, nil
}

// DecodeAuthorizationContextResolveRequest 严格解析内部授权上下文请求。
func DecodeAuthorizationContextResolveRequest(reader io.Reader) (AuthorizationContextResolveRequest, error) {
	var request AuthorizationContextResolveRequest
	if err := decodeResolverObject(reader, &request, "service", "company_id", "uin", "membership_epoch", "permissions"); err != nil {
		return request, err
	}
	if err := validateAuthorizationRequest(request); err != nil {
		return AuthorizationContextResolveRequest{}, ErrInvalidCredential
	}
	return request, nil
}

func validateAuthorizationRequest(request AuthorizationContextResolveRequest) error {
	if !validSessionResolveIdentifier(request.Service) || request.CompanyID == 0 || request.UIN == 0 || request.MembershipEpoch == 0 ||
		len(request.Permissions) > maximumAuthorizationPermissions {
		return ErrInvalidCredential
	}
	seen := make(map[PermissionCode]struct{}, len(request.Permissions))
	for _, permission := range request.Permissions {
		if !validPermissionCode(permission) {
			return ErrInvalidCredential
		}
		if _, duplicate := seen[permission]; duplicate {
			return ErrInvalidCredential
		}
		seen[permission] = struct{}{}
	}
	return nil
}

func validAuthorizationResponse(request AuthorizationContextResolveRequest, response AuthorizationContextResolveResponse) bool {
	if response.CompanyID != request.CompanyID || response.UIN != request.UIN || response.MembershipEpoch != request.MembershipEpoch ||
		len(response.Departments) > maximumAuthorizationDepartments || len(response.AllowedPermissions) > len(request.Permissions) {
		return false
	}
	requested := make(map[PermissionCode]struct{}, len(request.Permissions))
	for _, permission := range request.Permissions {
		requested[permission] = struct{}{}
	}
	allowed := make(map[PermissionCode]struct{}, len(response.AllowedPermissions))
	for _, permission := range response.AllowedPermissions {
		if _, ok := requested[permission]; !ok || !validPermissionCode(permission) {
			return false
		}
		if _, duplicate := allowed[permission]; duplicate {
			return false
		}
		allowed[permission] = struct{}{}
	}
	departments := make(map[uint]struct{}, len(response.Departments))
	for _, department := range response.Departments {
		if department.ID == 0 || department.Path == "" || department.Path[0] != '/' {
			return false
		}
		if _, duplicate := departments[department.ID]; duplicate {
			return false
		}
		departments[department.ID] = struct{}{}
	}
	return true
}

// ValidAuthorizationContextResponse 校验实现方返回的授权上下文严格属于原请求。
func ValidAuthorizationContextResponse(request AuthorizationContextResolveRequest, response AuthorizationContextResolveResponse) bool {
	return validAuthorizationResponse(request, response)
}

func validPermissionCode(permission PermissionCode) bool {
	value := string(permission)
	if len(value) < 3 || len(value) > 128 || value[0] == '.' || value[len(value)-1] == '.' {
		return false
	}
	dots := 0
	for _, character := range value {
		switch {
		case character == '.':
			dots++
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case character == '_':
		default:
			return false
		}
	}
	return dots == 1
}
