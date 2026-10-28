package logtodirectory

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

type wireSnapshot struct {
	Organization *wireOrganization `json:"organization"`
	Members      strictMembers     `json:"members"`
	Departments  strictDepartments `json:"departments"`
}

type wireListPage struct {
	Organization *wireOrganization `json:"organization"`
	Members      strictMembers     `json:"members"`
	Departments  strictDepartments `json:"departments"`
	NextCursor   json.RawMessage   `json:"next_cursor"`
}

type wireOrganizationSearch struct {
	Organizations []wireOrganization `json:"organizations"`
	NextCursor    json.RawMessage    `json:"next_cursor"`
}

type wireOrganization struct {
	ID   *string `json:"id"`
	Name *string `json:"name"`
}

type wireMember struct {
	UserID          *string         `json:"user_id"`
	Name            *string         `json:"name"`
	AvatarURL       *string         `json:"avatar_url"`
	Permissions     strictStrings   `json:"permissions"`
	DepartmentIDs   strictStrings   `json:"department_ids"`
	IsCompanyOwner  *bool           `json:"is_company_owner"`
	MembershipEpoch json.RawMessage `json:"membership_epoch"`
}

type wireDepartment struct {
	ID       *string `json:"id"`
	Name     *string `json:"name"`
	ParentID *string `json:"parent_id"`
}

func (response wireListPage) snapshot() wireSnapshot {
	return wireSnapshot{
		Organization: response.Organization,
		Members:      response.Members,
		Departments:  response.Departments,
	}
}

type strictStrings []string

func (values *strictStrings) UnmarshalJSON(document []byte) error {
	trimmed := bytes.TrimSpace(document)
	if bytes.Equal(trimmed, []byte("null")) || len(trimmed) == 0 || trimmed[0] != '[' {
		return errors.New("expected JSON array")
	}
	var decoded []string
	if err := json.Unmarshal(trimmed, &decoded); err != nil {
		return err
	}
	if decoded == nil {
		decoded = []string{}
	}
	*values = decoded
	return nil
}

type strictMembers []wireMember

func (members *strictMembers) UnmarshalJSON(document []byte) error {
	trimmed := bytes.TrimSpace(document)
	if bytes.Equal(trimmed, []byte("null")) || len(trimmed) == 0 || trimmed[0] != '[' {
		return errors.New("expected JSON array")
	}
	var objects []json.RawMessage
	if err := json.Unmarshal(trimmed, &objects); err != nil {
		return err
	}
	decoded := make([]wireMember, 0, len(objects))
	for _, object := range objects {
		trimmedObject := bytes.TrimSpace(object)
		if len(trimmedObject) == 0 || trimmedObject[0] != '{' {
			return errors.New("expected JSON object")
		}
		var member wireMember
		if err := strictJSON(trimmedObject, &member); err != nil {
			return err
		}
		decoded = append(decoded, member)
	}
	*members = decoded
	return nil
}

type strictDepartments []wireDepartment

func (departments *strictDepartments) UnmarshalJSON(document []byte) error {
	trimmed := bytes.TrimSpace(document)
	if bytes.Equal(trimmed, []byte("null")) || len(trimmed) == 0 || trimmed[0] != '[' {
		return errors.New("expected JSON array")
	}
	var objects []json.RawMessage
	if err := json.Unmarshal(trimmed, &objects); err != nil {
		return err
	}
	decoded := make([]wireDepartment, 0, len(objects))
	for _, object := range objects {
		trimmedObject := bytes.TrimSpace(object)
		if len(trimmedObject) == 0 || trimmedObject[0] != '{' {
			return errors.New("expected JSON object")
		}
		var department wireDepartment
		if err := strictJSON(trimmedObject, &department); err != nil {
			return err
		}
		decoded = append(decoded, department)
	}
	*departments = decoded
	return nil
}

type snapshotValidation struct {
	organizationID string
	requested      map[string]struct{}
	listMode       bool
	cursor         string
	limit          int
	options        Options
}

func validateSnapshot(response wireSnapshot, validation snapshotValidation) (Snapshot, error) {
	if response.Organization == nil || response.Organization.ID == nil || response.Organization.Name == nil ||
		*response.Organization.ID != validation.organizationID || !displayValue(*response.Organization.Name, 128, false) ||
		response.Members == nil || response.Departments == nil || len(response.Members) > maxMembers ||
		(validation.listMode && len(response.Members) > validation.limit) {
		return Snapshot{}, ErrProtocol
	}

	members := make([]Member, 0, len(response.Members))
	seenMembers := make(map[string]struct{}, len(response.Members))
	previousMemberID := ""
	for _, member := range response.Members {
		if member.UserID == nil || member.Name == nil || member.AvatarURL == nil || member.IsCompanyOwner == nil ||
			!canonicalValue(*member.UserID, maxMemberIDRunes) || !displayValue(*member.Name, 128, false) ||
			!validAvatar(*member.AvatarURL) || member.Permissions == nil || member.DepartmentIDs == nil ||
			len(member.Permissions) > maxPermissions || len(member.DepartmentIDs) > maxDirectDepartments {
			return Snapshot{}, ErrProtocol
		}
		if _, duplicate := seenMembers[*member.UserID]; duplicate {
			return Snapshot{}, ErrProtocol
		}
		seenMembers[*member.UserID] = struct{}{}
		if validation.listMode {
			if validation.cursor != "" && *member.UserID <= validation.cursor {
				return Snapshot{}, ErrProtocol
			}
			if previousMemberID != "" && *member.UserID <= previousMemberID {
				return Snapshot{}, ErrProtocol
			}
			previousMemberID = *member.UserID
		} else if _, requested := validation.requested[*member.UserID]; !requested {
			return Snapshot{}, ErrProtocol
		}

		permissions := append([]string{}, member.Permissions...)
		seenPermissions := make(map[string]struct{}, len(permissions))
		for _, permission := range permissions {
			if !canonicalValue(permission, maxPermissionRunes) {
				return Snapshot{}, ErrProtocol
			}
			if _, duplicate := seenPermissions[permission]; duplicate {
				return Snapshot{}, ErrProtocol
			}
			seenPermissions[permission] = struct{}{}
		}

		departmentIDs := append([]string{}, member.DepartmentIDs...)
		seenDepartments := make(map[string]struct{}, len(departmentIDs))
		for _, departmentID := range departmentIDs {
			if !canonicalValue(departmentID, maxDepartmentIDRunes) {
				return Snapshot{}, ErrProtocol
			}
			if _, duplicate := seenDepartments[departmentID]; duplicate {
				return Snapshot{}, ErrProtocol
			}
			seenDepartments[departmentID] = struct{}{}
		}

		membershipEpoch, err := parseMembershipEpoch(member.MembershipEpoch, validation.options.IncludeMembershipEpoch)
		if err != nil {
			return Snapshot{}, ErrProtocol
		}
		members = append(members, Member{
			UserID: *member.UserID, Name: *member.Name, AvatarURL: *member.AvatarURL,
			Permissions: permissions, DepartmentIDs: departmentIDs,
			IsCompanyOwner: *member.IsCompanyOwner, MembershipEpoch: membershipEpoch,
		})
	}

	if !validation.options.IncludeDepartments && len(response.Departments) != 0 {
		return Snapshot{}, ErrProtocol
	}
	if len(response.Departments) > maxDepartments {
		return Snapshot{}, ErrProtocol
	}
	departments := make([]Department, 0, len(response.Departments))
	seenDepartmentIDs := make(map[string]struct{}, len(response.Departments))
	for index := range response.Departments {
		decoded := response.Departments[index]
		if decoded.ID == nil || decoded.Name == nil || !canonicalValue(*decoded.ID, maxDepartmentIDRunes) ||
			!displayValue(*decoded.Name, 128, false) {
			return Snapshot{}, ErrProtocol
		}
		if _, duplicate := seenDepartmentIDs[*decoded.ID]; duplicate {
			return Snapshot{}, ErrProtocol
		}
		seenDepartmentIDs[*decoded.ID] = struct{}{}
		departments = append(departments, Department{
			ID: *decoded.ID, Name: *decoded.Name, ParentID: cloneStringPointer(decoded.ParentID),
		})
	}
	byID := make(map[string]*Department, len(departments))
	for index := range departments {
		department := &departments[index]
		byID[department.ID] = department
	}
	for _, department := range departments {
		if department.ParentID == nil {
			continue
		}
		if !canonicalValue(*department.ParentID, maxDepartmentIDRunes) || *department.ParentID == department.ID {
			return Snapshot{}, ErrProtocol
		}
		if _, exists := byID[*department.ParentID]; !exists {
			return Snapshot{}, ErrProtocol
		}
	}
	if validation.options.IncludeDepartments {
		for _, member := range members {
			for _, departmentID := range member.DepartmentIDs {
				if _, exists := byID[departmentID]; !exists {
					return Snapshot{}, ErrProtocol
				}
			}
		}
	}
	for departmentID := range byID {
		visited := make(map[string]struct{}, 16)
		current := departmentID
		for {
			if _, duplicate := visited[current]; duplicate {
				return Snapshot{}, ErrProtocol
			}
			visited[current] = struct{}{}
			department := byID[current]
			if department == nil {
				return Snapshot{}, ErrProtocol
			}
			if department.ParentID == nil {
				break
			}
			current = *department.ParentID
		}
	}
	return Snapshot{Organization: Organization{ID: *response.Organization.ID, Name: *response.Organization.Name}, Members: members, Departments: departments}, nil
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func parseMembershipEpoch(raw json.RawMessage, requested bool) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		if requested {
			return "", ErrProtocol
		}
		return "", nil
	}
	if !requested || trimmed[0] != '"' {
		return "", ErrProtocol
	}
	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil || !canonicalPositiveInt64(value) {
		return "", ErrProtocol
	}
	return value, nil
}

func canonicalPositiveInt64(value string) bool {
	if value == "" || value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	_, err := strconv.ParseInt(value, 10, 64)
	return err == nil
}

func parseOptionalString(raw json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", nil
	}
	if bytes.Equal(trimmed, []byte("null")) || trimmed[0] != '"' {
		return "", ErrProtocol
	}
	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return "", ErrProtocol
	}
	return value, nil
}

func parseNextCursor(raw json.RawMessage) (*string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, ErrProtocol
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if trimmed[0] != '"' {
		return nil, ErrProtocol
	}
	var cursor string
	if err := json.Unmarshal(trimmed, &cursor); err != nil || !canonicalValue(cursor, maxMemberIDRunes) {
		return nil, ErrProtocol
	}
	return &cursor, nil
}

func parseOptionalOrganizationCursor(raw json.RawMessage) (*string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if bytes.Equal(trimmed, []byte("null")) || trimmed[0] != '"' {
		return nil, ErrProtocol
	}
	var cursor string
	if err := json.Unmarshal(trimmed, &cursor); err != nil || !validOrganizationID(cursor) {
		return nil, ErrProtocol
	}
	return &cursor, nil
}

func validateOrganizationSearch(organizations []wireOrganization, cursor string, nextCursor *string, limit int) ([]Organization, error) {
	if organizations == nil || len(organizations) > maxOrganizations || len(organizations) > limit {
		return nil, ErrProtocol
	}
	validated := make([]Organization, 0, len(organizations))
	seen := make(map[string]struct{}, len(organizations))
	previousID := ""
	for _, organization := range organizations {
		if organization.ID == nil || organization.Name == nil || !validOrganizationID(*organization.ID) ||
			!displayValue(*organization.Name, 128, false) {
			return nil, ErrProtocol
		}
		if _, duplicate := seen[*organization.ID]; duplicate ||
			(previousID != "" && *organization.ID <= previousID) ||
			(cursor != "" && *organization.ID <= cursor) {
			return nil, ErrProtocol
		}
		seen[*organization.ID] = struct{}{}
		previousID = *organization.ID
		validated = append(validated, Organization{ID: *organization.ID, Name: *organization.Name})
	}
	if nextCursor != nil && (len(validated) == 0 || *nextCursor < validated[len(validated)-1].ID) {
		return nil, ErrProtocol
	}
	return validated, nil
}

func strictJSON(document []byte, target any) error {
	if !utf8.Valid(document) {
		return errors.New("invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
