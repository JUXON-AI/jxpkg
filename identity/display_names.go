package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

const _maximumDisplayNameBytes = 512

var errInvalidDisplayNames = errors.New("invalid identity display names")

// DisplayNames 是绑定组织成员的展示元数据，不包含授权或身份准入语义。
type DisplayNames struct {
	// Username 是用于 NewAPI 账户展示的用户名。
	Username string `json:"username"`
	// OrganizationName 是用于 NewAPI 账户展示的公司名。
	OrganizationName string `json:"organization_name"`
}

// UnmarshalJSON 只接受 username 与 organization_name 两个字符串字段，并拒绝歧义对象。
func (value *DisplayNames) UnmarshalJSON(raw []byte) error {
	if value == nil || !utf8.Valid(raw) {
		return errInvalidDisplayNames
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errInvalidDisplayNames
	}
	seen := make(map[string]bool, 2)
	var username, organizationName *string
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return errInvalidDisplayNames
		}
		seen[name] = true
		switch name {
		case "username":
			err = decoder.Decode(&username)
		case "organization_name":
			err = decoder.Decode(&organizationName)
		default:
			return errInvalidDisplayNames
		}
		if err != nil {
			return errInvalidDisplayNames
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errInvalidDisplayNames
	}
	if _, err := decoder.Token(); err != io.EOF || username == nil || organizationName == nil {
		return errInvalidDisplayNames
	}
	decoded := DisplayNames{Username: *username, OrganizationName: *organizationName}
	if err := decoded.Validate(); err != nil {
		return errInvalidDisplayNames
	}
	*value = decoded
	return nil
}

// Validate 验证展示名非空、编码与控制字符合法，且每个字段不超过 512 字节。
func (value DisplayNames) Validate() error {
	for _, field := range []string{value.Username, value.OrganizationName} {
		if strings.TrimSpace(field) == "" || len(field) > _maximumDisplayNameBytes || !utf8.ValidString(field) {
			return errInvalidDisplayNames
		}
		for _, character := range field {
			if unicode.IsControl(character) {
				return errInvalidDisplayNames
			}
		}
	}
	return nil
}

type displayNamesContextKey struct{}

type displayNamesContextValue struct {
	member Member
	names  DisplayNames
}

// WithDisplayNames 将经过校验的展示名绑定到同一组织成员，并在保存前裁剪首尾空白。
func WithDisplayNames(ctx context.Context, member Member, names DisplayNames) (context.Context, error) {
	if err := member.Validate(); err != nil {
		return ctx, err
	}
	if err := names.Validate(); err != nil {
		return ctx, err
	}
	names.Username = strings.TrimSpace(names.Username)
	names.OrganizationName = strings.TrimSpace(names.OrganizationName)
	if ctx == nil {
		return nil, errInvalidDisplayNames
	}
	return context.WithValue(ctx, displayNamesContextKey{}, displayNamesContextValue{member: member, names: names}), nil
}

// DisplayNamesFromContext 返回与成员组织和用户都匹配的有效展示名；不授予任何访问权限。
func DisplayNamesFromContext(ctx context.Context, member Member) (DisplayNames, bool) {
	if ctx == nil || member.Validate() != nil {
		return DisplayNames{}, false
	}
	stored, ok := ctx.Value(displayNamesContextKey{}).(displayNamesContextValue)
	if !ok || stored.member != member || stored.names.Validate() != nil {
		return DisplayNames{}, false
	}
	return stored.names, true
}
