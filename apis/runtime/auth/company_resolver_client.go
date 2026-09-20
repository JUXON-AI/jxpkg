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
	"strings"
	"unicode/utf8"
)

const (
	// InternalCompanySearchPath 是 Account 内部公司目录搜索接口的固定路径。
	InternalCompanySearchPath = "/internal/company/search"
	// InternalCompanyResolvePath 是 Account 内部公司解析接口的固定路径。
	InternalCompanyResolvePath = "/internal/company/resolve"

	maximumCompanySearchQueryRunes     = 128
	maximumCompanySearchResults        = 20
	maximumCompanySearchResponseBytes  = 256 * 1024
	maximumCompanyResolveResponseBytes = 64 * 1024
)

// CompanySummary 表示 Account 权威的最小可用公司目录快照。
type CompanySummary struct {
	// CompanyID 表示公司标识。
	CompanyID uint `json:"company_id"`
	// Name 表示公司显示名称。
	Name string `json:"name"`
}

// CompanySearchRequest 描述按关键词搜索可用公司的输入。
type CompanySearchRequest struct {
	// Service 表示调用方在 Account 工作负载注册表中的静态服务标识。
	Service string `json:"service"`
	// Query 表示用于匹配公司名称的关键词。
	Query string `json:"query"`
	// Limit 表示最多返回的公司数量，取值范围为 1 到 20。
	Limit int `json:"limit"`
}

// CompanySearchResponse 表示一次公司目录搜索的权威结果。
type CompanySearchResponse struct {
	// Companies 表示按权重稳定排序的可用公司。
	Companies []CompanySummary `json:"companies"`
}

// CompanyResolveRequest 描述按公司 ID 解析公司的输入。
type CompanyResolveRequest struct {
	// Service 表示调用方在 Account 工作负载注册表中的静态服务标识。
	Service string `json:"service"`
	// CompanyID 表示待解析的公司标识。
	CompanyID uint `json:"company_id"`
}

// CompanyResolveResponse 表示单个公司的权威快照。
type CompanyResolveResponse struct {
	// CompanyID 表示被解析的公司标识。
	CompanyID uint `json:"company_id"`
	// Name 表示公司显示名称。
	Name string `json:"name"`
}

// CompanyResolver 读取 Account 权威的可用公司目录，供跨组织授权目标选择与校验。
type CompanyResolver interface {
	SearchCompanies(context.Context, CompanySearchRequest) (*CompanySearchResponse, error)
	ResolveCompany(context.Context, CompanyResolveRequest) (*CompanyResolveResponse, error)
}

var _ CompanyResolver = (*InternalSessionResolverClient)(nil)

// SearchCompanies 使用与 Session Resolve 相同的 mTLS 客户端搜索可用公司。
func (client *InternalSessionResolverClient) SearchCompanies(ctx context.Context, request CompanySearchRequest) (*CompanySearchResponse, error) {
	if client == nil || client.client == nil || client.companySearchEndpoint == "" {
		return nil, fmt.Errorf("%w: company search resolver is not configured", ErrAuthBackendUnavailable)
	}
	request.Service = client.service
	request.Query = strings.TrimSpace(request.Query)
	if !validCompanySearchRequest(request) {
		return nil, ErrInvalidCredential
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%w: encode company search request", ErrAuthBackendUnavailable)
	}
	reply, err := client.doResolver(ctx, client.companySearchEndpoint, body, maximumCompanySearchResponseBytes)
	if err != nil {
		return nil, err
	}
	switch {
	case reply.status == http.StatusUnauthorized || reply.status == http.StatusForbidden || reply.status == http.StatusNotFound:
		return nil, ErrAuthorizationDenied
	case reply.status != http.StatusOK:
		return nil, fmt.Errorf("%w: company search returned status %d", ErrAuthBackendUnavailable, reply.status)
	}
	var result CompanySearchResponse
	decoder := json.NewDecoder(bytes.NewReader(reply.document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || !ValidCompanySearchResponse(request, result) {
		return nil, fmt.Errorf("%w: decode company search response", ErrAuthBackendUnavailable)
	}
	if result.Companies == nil {
		result.Companies = []CompanySummary{}
	}
	return &result, nil
}

// ResolveCompany 使用与 Session Resolve 相同的 mTLS 客户端解析单个可用公司。
func (client *InternalSessionResolverClient) ResolveCompany(ctx context.Context, request CompanyResolveRequest) (*CompanyResolveResponse, error) {
	if client == nil || client.client == nil || client.companyResolveEndpoint == "" {
		return nil, fmt.Errorf("%w: company resolver is not configured", ErrAuthBackendUnavailable)
	}
	request.Service = client.service
	if !validCompanyResolveRequest(request) {
		return nil, ErrInvalidCredential
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%w: encode company resolve request", ErrAuthBackendUnavailable)
	}
	reply, err := client.doResolver(ctx, client.companyResolveEndpoint, body, maximumCompanyResolveResponseBytes)
	if err != nil {
		return nil, err
	}
	switch {
	case reply.status == http.StatusNotFound:
		return nil, ErrCompanyNotFound
	case reply.status == http.StatusUnauthorized || reply.status == http.StatusForbidden:
		return nil, ErrAuthorizationDenied
	case reply.status != http.StatusOK:
		return nil, fmt.Errorf("%w: company resolve returned status %d", ErrAuthBackendUnavailable, reply.status)
	}
	var result CompanyResolveResponse
	decoder := json.NewDecoder(bytes.NewReader(reply.document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || !ValidCompanyResolveResponse(request, result) {
		return nil, fmt.Errorf("%w: decode company resolve response", ErrAuthBackendUnavailable)
	}
	return &result, nil
}

type resolverReply struct {
	status   int
	document []byte
}

// doResolver 执行一次内部 resolver 请求；无论状态码如何都会关闭响应体。
func (client *InternalSessionResolverClient) doResolver(ctx context.Context, endpoint string, body []byte, maximumBytes int64) (resolverReply, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return resolverReply{}, fmt.Errorf("%w: create resolver request", ErrAuthBackendUnavailable)
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Cache-Control", "no-store")
	response, err := client.client.Do(httpRequest)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return resolverReply{}, fmt.Errorf("%w: %w", ErrAuthBackendUnavailable, ctxErr)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return resolverReply{}, fmt.Errorf("%w: %w", ErrAuthBackendUnavailable, context.DeadlineExceeded)
		}
		return resolverReply{}, fmt.Errorf("%w: resolver transport", ErrAuthBackendUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return resolverReply{status: response.StatusCode}, nil
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || response.ContentLength > maximumBytes {
		return resolverReply{}, fmt.Errorf("%w: invalid resolver response metadata", ErrAuthBackendUnavailable)
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, maximumBytes+1))
	if err != nil || int64(len(document)) > maximumBytes || validateJSONObject(document) != nil {
		return resolverReply{}, fmt.Errorf("%w: invalid resolver response body", ErrAuthBackendUnavailable)
	}
	return resolverReply{status: response.StatusCode, document: document}, nil
}

// DecodeCompanySearchRequest 严格解析内部公司搜索请求。
func DecodeCompanySearchRequest(reader io.Reader) (CompanySearchRequest, error) {
	var request CompanySearchRequest
	if err := decodeResolverObject(reader, &request, "service", "query", "limit"); err != nil {
		return CompanySearchRequest{}, ErrInvalidCredential
	}
	request.Query = strings.TrimSpace(request.Query)
	if !validCompanySearchRequest(request) {
		return CompanySearchRequest{}, ErrInvalidCredential
	}
	return request, nil
}

// DecodeCompanyResolveRequest 严格解析内部公司解析请求。
func DecodeCompanyResolveRequest(reader io.Reader) (CompanyResolveRequest, error) {
	var request CompanyResolveRequest
	if err := decodeResolverObject(reader, &request, "service", "company_id"); err != nil || !validCompanyResolveRequest(request) {
		return CompanyResolveRequest{}, ErrInvalidCredential
	}
	return request, nil
}

func validCompanySearchRequest(request CompanySearchRequest) bool {
	return validSessionResolveIdentifier(request.Service) &&
		request.Query != "" && utf8.ValidString(request.Query) && utf8.RuneCountInString(request.Query) <= maximumCompanySearchQueryRunes &&
		request.Limit > 0 && request.Limit <= maximumCompanySearchResults
}

func validCompanyResolveRequest(request CompanyResolveRequest) bool {
	return validSessionResolveIdentifier(request.Service) && request.CompanyID != 0
}

// ValidCompanySearchResponse 校验搜索响应属于原请求、数量有界且不存在重复公司。
func ValidCompanySearchResponse(request CompanySearchRequest, response CompanySearchResponse) bool {
	if request.Limit <= 0 || request.Limit > maximumCompanySearchResults || len(response.Companies) > request.Limit {
		return false
	}
	seen := make(map[uint]struct{}, len(response.Companies))
	for _, company := range response.Companies {
		if !validCompanySummary(company) {
			return false
		}
		if _, duplicate := seen[company.CompanyID]; duplicate {
			return false
		}
		seen[company.CompanyID] = struct{}{}
	}
	return true
}

// ValidCompanyResolveResponse 校验解析响应与原请求指向同一公司。
func ValidCompanyResolveResponse(request CompanyResolveRequest, response CompanyResolveResponse) bool {
	return response.CompanyID == request.CompanyID && validCompanySummary(CompanySummary{CompanyID: response.CompanyID, Name: response.Name})
}

func validCompanySummary(company CompanySummary) bool {
	return company.CompanyID != 0 && company.Name != "" && utf8.ValidString(company.Name) && len(company.Name) <= 255
}
