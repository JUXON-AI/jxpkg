package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
)

const (
	// InternalAuthorizationSubjectsResolvePath 是 Account 授权主体目录的固定内部路径。
	InternalAuthorizationSubjectsResolvePath  = "/internal/authorization-subjects/resolve"
	maximumAuthorizationSubjects              = 1000
	maximumAuthorizationSubjectsResponseBytes = 512 * 1024
)

// AuthorizationSubjectsResolveRequest 描述读取当前组织授权候选所需身份作用域。
type AuthorizationSubjectsResolveRequest struct {
	Service         string `json:"service"`
	CompanyID       uint   `json:"company_id"`
	UIN             uint   `json:"uin"`
	MembershipEpoch uint64 `json:"membership_epoch"`
}

// AuthorizationUser 表示可作为资源授权主体的有效公司身份。
type AuthorizationUser struct {
	UIN      uint   `json:"uin"`
	Username string `json:"username"`
}

// AuthorizationSubjectDepartment 表示可作为资源授权主体的有效部门。
type AuthorizationSubjectDepartment struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
}

// AuthorizationSubjectsResolveResponse 表示 Account 权威的同组织授权主体目录。
type AuthorizationSubjectsResolveResponse struct {
	CompanyID       uint                             `json:"company_id"`
	UIN             uint                             `json:"uin"`
	MembershipEpoch uint64                           `json:"membership_epoch"`
	Users           []AuthorizationUser              `json:"users"`
	Departments     []AuthorizationSubjectDepartment `json:"departments"`
}

// AuthorizationSubjectsResolver 读取当前组织可被资源服务授权的有效主体。
type AuthorizationSubjectsResolver interface {
	ResolveAuthorizationSubjects(context.Context, AuthorizationSubjectsResolveRequest) (*AuthorizationSubjectsResolveResponse, error)
}

var _ AuthorizationSubjectsResolver = (*InternalSessionResolverClient)(nil)

// ResolveAuthorizationSubjects 使用受认证的内部客户端读取最小授权主体目录。
func (client *InternalSessionResolverClient) ResolveAuthorizationSubjects(ctx context.Context, request AuthorizationSubjectsResolveRequest) (*AuthorizationSubjectsResolveResponse, error) {
	if client == nil || client.client == nil || client.authorizationSubjectsEndpoint == "" {
		return nil, fmt.Errorf("%w: authorization subjects resolver is not configured", ErrAuthBackendUnavailable)
	}
	request.Service = client.service
	if !validAuthorizationSubjectsRequest(request) {
		return nil, ErrInvalidCredential
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%w: encode authorization subjects request", ErrAuthBackendUnavailable)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.authorizationSubjectsEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: create authorization subjects request", ErrAuthBackendUnavailable)
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Cache-Control", "no-store")
	response, err := client.client.Do(httpRequest)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrAuthBackendUnavailable, ctxErr)
		}
		return nil, fmt.Errorf("%w: authorization subjects transport", ErrAuthBackendUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound {
		return nil, ErrAuthorizationDenied
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: authorization subjects returned status %d", ErrAuthBackendUnavailable, response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || response.ContentLength > maximumAuthorizationSubjectsResponseBytes {
		return nil, fmt.Errorf("%w: invalid authorization subjects metadata", ErrAuthBackendUnavailable)
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, maximumAuthorizationSubjectsResponseBytes+1))
	if err != nil || len(document) > maximumAuthorizationSubjectsResponseBytes || validateJSONObject(document) != nil {
		return nil, fmt.Errorf("%w: invalid authorization subjects response", ErrAuthBackendUnavailable)
	}
	var result AuthorizationSubjectsResolveResponse
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || !ValidAuthorizationSubjectsResponse(request, result) {
		return nil, fmt.Errorf("%w: decode authorization subjects response", ErrAuthBackendUnavailable)
	}
	return &result, nil
}

// DecodeAuthorizationSubjectsResolveRequest 严格解析内部授权主体目录请求。
func DecodeAuthorizationSubjectsResolveRequest(reader io.Reader) (AuthorizationSubjectsResolveRequest, error) {
	var request AuthorizationSubjectsResolveRequest
	if err := decodeResolverObject(reader, &request, "service", "company_id", "uin", "membership_epoch"); err != nil || !validAuthorizationSubjectsRequest(request) {
		return AuthorizationSubjectsResolveRequest{}, ErrInvalidCredential
	}
	return request, nil
}

func validAuthorizationSubjectsRequest(request AuthorizationSubjectsResolveRequest) bool {
	return validSessionResolveIdentifier(request.Service) && request.CompanyID != 0 && request.UIN != 0 && request.MembershipEpoch != 0
}

// ValidAuthorizationSubjectsResponse 校验授权主体目录严格属于原请求且不存在重复主体。
func ValidAuthorizationSubjectsResponse(request AuthorizationSubjectsResolveRequest, response AuthorizationSubjectsResolveResponse) bool {
	if response.CompanyID != request.CompanyID || response.UIN != request.UIN || response.MembershipEpoch != request.MembershipEpoch || len(response.Users) > maximumAuthorizationSubjects || len(response.Departments) > maximumAuthorizationSubjects {
		return false
	}
	users := make(map[uint]struct{}, len(response.Users))
	for _, user := range response.Users {
		if user.UIN == 0 || user.Username == "" {
			return false
		}
		if _, exists := users[user.UIN]; exists {
			return false
		}
		users[user.UIN] = struct{}{}
	}
	departments := make(map[uint]struct{}, len(response.Departments))
	for _, department := range response.Departments {
		if department.ID == 0 || department.Name == "" || department.Path == "" || department.Path[0] != '/' {
			return false
		}
		if _, exists := departments[department.ID]; exists {
			return false
		}
		departments[department.ID] = struct{}{}
	}
	return true
}
