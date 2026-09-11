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
	// InternalCompanyIdentityResolvePath 是 Account 内部公司身份批量解析接口的固定路径。
	InternalCompanyIdentityResolvePath = "/internal/company-identities/resolve"

	maximumCompanyIdentityCount         = 256
	maximumCompanyIdentityResponseBytes = 512 * 1024
)

// CompanyIdentityStatus 表示 Account 权威公司身份的当前状态。
type CompanyIdentityStatus string

const (
	// CompanyIdentityStatusPending 表示身份尚未激活，不能访问业务资源。
	CompanyIdentityStatusPending CompanyIdentityStatus = "pending"

	// CompanyIdentityStatusActive 表示身份当前可以访问所属公司的业务资源。
	CompanyIdentityStatusActive CompanyIdentityStatus = "active"

	// CompanyIdentityStatusDisabled 表示身份已由管理员停用。
	CompanyIdentityStatusDisabled CompanyIdentityStatus = "disabled"

	// CompanyIdentityStatusLeft 表示身份已离开公司。
	CompanyIdentityStatusLeft CompanyIdentityStatus = "left"
)

// CompanyIdentity 表示业务服务执行成员授权所需的最小 Account 身份快照。
type CompanyIdentity struct {
	// UIN 表示身份在 Account 中的公司内标识。
	UIN uint `json:"uin"`

	// MembershipEpoch 表示身份重新加入公司时单调递增的授权代次。
	MembershipEpoch uint64 `json:"membership_epoch"`

	// Username 表示身份在公司内的显示名称。
	Username string `json:"username"`

	// AvatarURL 表示身份在公司内的头像地址。
	AvatarURL string `json:"avatar_url"`

	// Status 表示身份当前是否可用于访问业务资源。
	Status CompanyIdentityStatus `json:"status"`

	// IsCompanyOwner 表示该身份是否是公司的当前权威所有者。
	IsCompanyOwner bool `json:"is_company_owner"`
}

// CompanyIdentityResolveRequest 描述业务服务批量解析公司身份所需的输入。
type CompanyIdentityResolveRequest struct {
	// Service 表示调用方在 Account 工作负载注册表中的静态服务标识。
	Service string `json:"service"`

	// CompanyID 表示所有目标身份必须所属的公司。
	CompanyID uint `json:"company_id"`

	// UINs 表示待解析的去重公司身份标识，最多允许 256 个。
	UINs []uint `json:"uins"`
}

// CompanyIdentityResolver 批量返回 Account 权威的最小公司身份快照。
type CompanyIdentityResolver interface {
	ResolveCompanyIdentities(context.Context, CompanyIdentityResolveRequest) ([]CompanyIdentity, error)
}

// CompanyIdentityResolveResponse binds the returned identity list to its company.
type CompanyIdentityResolveResponse struct {
	// CompanyID identifies the company requested by the authenticated caller.
	CompanyID uint `json:"company_id"`
	// Identities contains existing requested identities and never placeholder rows.
	Identities []CompanyIdentity `json:"identities"`
}

var _ CompanyIdentityResolver = (*InternalSessionResolverClient)(nil)

// ResolveCompanyIdentities 使用与 Session Resolve 相同的 mTLS 客户端批量读取公司身份。
// 响应只包含仍存在的目标 UIN；调用方必须把缺失身份当作不可授权，而不能降级使用缓存值。
func (client *InternalSessionResolverClient) ResolveCompanyIdentities(
	ctx context.Context, request CompanyIdentityResolveRequest,
) ([]CompanyIdentity, error) {
	if client == nil || client.client == nil || client.companyIdentityEndpoint == "" {
		return nil, fmt.Errorf("%w: company identity resolver client is not configured", ErrAuthBackendUnavailable)
	}
	if request.Service != client.service || request.CompanyID == 0 || len(request.UINs) == 0 || len(request.UINs) > maximumCompanyIdentityCount {
		return nil, ErrInvalidCredential
	}
	requested := make(map[uint]struct{}, len(request.UINs))
	for _, uin := range request.UINs {
		if uin == 0 {
			return nil, ErrInvalidCredential
		}
		if _, duplicate := requested[uin]; duplicate {
			return nil, ErrInvalidCredential
		}
		requested[uin] = struct{}{}
	}
	body, err := json.Marshal(CompanyIdentityResolveRequest{
		Service: client.service, CompanyID: request.CompanyID, UINs: request.UINs,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode company identity request", ErrAuthBackendUnavailable)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.companyIdentityEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: create company identity request", ErrAuthBackendUnavailable)
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Cache-Control", "no-store")

	response, err := client.client.Do(httpRequest)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrAuthBackendUnavailable, ctxErr)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: %w", ErrAuthBackendUnavailable, context.DeadlineExceeded)
		}
		return nil, fmt.Errorf("%w: company identity resolve transport", ErrAuthBackendUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: company identity resolve returned status %d", ErrAuthBackendUnavailable, response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, fmt.Errorf("%w: invalid company identity content type", ErrAuthBackendUnavailable)
	}
	if response.ContentLength > maximumCompanyIdentityResponseBytes {
		return nil, fmt.Errorf("%w: company identity response is too large", ErrAuthBackendUnavailable)
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, maximumCompanyIdentityResponseBytes+1))
	if err != nil || len(document) > maximumCompanyIdentityResponseBytes {
		return nil, fmt.Errorf("%w: read company identity response", ErrAuthBackendUnavailable)
	}
	if err := validateJSONObject(document); err != nil {
		return nil, fmt.Errorf("%w: invalid company identity response", ErrAuthBackendUnavailable)
	}
	var wire CompanyIdentityResolveResponse
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || wire.CompanyID != request.CompanyID || len(wire.Identities) > len(request.UINs) {
		return nil, fmt.Errorf("%w: decode company identity response", ErrAuthBackendUnavailable)
	}

	seen := make(map[uint]struct{}, len(wire.Identities))
	identities := make([]CompanyIdentity, 0, len(wire.Identities))
	for _, identity := range wire.Identities {
		if identity.UIN == 0 || identity.MembershipEpoch == 0 || !validCompanyIdentityStatus(identity.Status) {
			return nil, fmt.Errorf("%w: invalid company identity", ErrAuthBackendUnavailable)
		}
		if _, requestedIdentity := requested[identity.UIN]; !requestedIdentity {
			return nil, fmt.Errorf("%w: unexpected company identity", ErrAuthBackendUnavailable)
		}
		if _, duplicate := seen[identity.UIN]; duplicate {
			return nil, fmt.Errorf("%w: duplicate company identity", ErrAuthBackendUnavailable)
		}
		if identity.IsCompanyOwner && identity.Status != CompanyIdentityStatusActive {
			return nil, fmt.Errorf("%w: inactive company owner", ErrAuthBackendUnavailable)
		}
		seen[identity.UIN] = struct{}{}
		identities = append(identities, CompanyIdentity{
			UIN: identity.UIN, MembershipEpoch: identity.MembershipEpoch,
			Username: identity.Username, AvatarURL: identity.AvatarURL, Status: identity.Status,
			IsCompanyOwner: identity.IsCompanyOwner,
		})
	}
	return identities, nil
}

func validCompanyIdentityStatus(status CompanyIdentityStatus) bool {
	return status == CompanyIdentityStatusPending || status == CompanyIdentityStatusActive ||
		status == CompanyIdentityStatusDisabled || status == CompanyIdentityStatusLeft
}
