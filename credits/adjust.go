package credits

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// AdminAdjustPath is the workload-only quota adjustment route.
	AdminAdjustPath = "/internal/credits/admin-adjust"
	// AdminAdjustResultPath reads one durable adjustment receipt without dispatching a write.
	AdminAdjustResultPath = "/internal/credits/admin-adjust/result"
)

const (
	// AdminAdjustmentDispatching means one upstream write may have started; it must never be automatically replayed.
	AdminAdjustmentDispatching AdminAdjustmentState = "dispatching"
	// AdminAdjustmentApplied means New API accepted the write.
	AdminAdjustmentApplied AdminAdjustmentState = "applied"
	// AdminAdjustmentRejected means New API definitely rejected the write.
	AdminAdjustmentRejected AdminAdjustmentState = "rejected"
	// AdminAdjustmentUnknown means the committed result could not be proven.
	AdminAdjustmentUnknown AdminAdjustmentState = "unknown"
)

// AdminAdjustmentState is the fixed protocol state for one adjustment receipt.
type AdminAdjustmentState string

var _adminOperationIDPattern = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// AdminAdjustRequest is the raw workload request for one signed quota adjustment.
type AdminAdjustRequest struct {
	// OrganizationID is the verified native organization subject.
	OrganizationID string `json:"organization_id"`
	// UserID is the verified native user subject.
	UserID string `json:"user_id"`
	// OperationID deduplicates all retries of one adjustment intent.
	OperationID string `json:"operation_id"`
	// Delta is a non-zero signed New API quota change; positive adds and negative subtracts.
	Delta int64 `json:"delta"`
	// ActorID identifies the trusted human administrator for attribution only.
	ActorID string `json:"actor_id"`
	// Reason is the bounded human-readable adjustment reason.
	Reason string `json:"reason"`
}

// AdminAdjustLookup identifies one stored adjustment receipt.
type AdminAdjustLookup struct {
	// OrganizationID is the native organization subject bound to the receipt.
	OrganizationID string `json:"organization_id"`
	// UserID is the native user subject bound to the receipt.
	UserID string `json:"user_id"`
	// OperationID is the durable operation identity.
	OperationID string `json:"operation_id"`
}

// AdminAdjustment is the immutable outcome known for one adjustment operation.
type AdminAdjustment struct {
	// State is dispatching, applied, rejected, or unknown.
	State AdminAdjustmentState `json:"state"`
	// OperationID is the durable operation identity.
	OperationID string `json:"operation_id"`
	// OrganizationID is the native organization subject bound to the receipt.
	OrganizationID string `json:"organization_id"`
	// UserID is the native user subject bound to the receipt.
	UserID string `json:"user_id"`
	// Delta is the signed New API quota change.
	Delta int64 `json:"delta"`
	// ActorID is the caller-attributed human administrator.
	ActorID string `json:"actor_id"`
	// Reason is the persisted adjustment reason.
	Reason string `json:"reason"`
}

// Validate verifies one adjustment request at its transport entry point.
func (r AdminAdjustRequest) Validate() error {
	subject := Subject{OrganizationID: r.OrganizationID, UserID: r.UserID}
	if subject.Validate() != nil || !_adminOperationIDPattern.MatchString(r.OperationID) || r.Delta == 0 || r.Delta < -_maxAdminExactInteger || r.Delta > _maxAdminExactInteger || !validAdminAttribution(r.ActorID, 128) || !validReason(r.Reason) {
		return ErrDenied
	}
	return nil
}

// Validate verifies one durable receipt lookup.
func (l AdminAdjustLookup) Validate() error {
	subject := Subject{OrganizationID: l.OrganizationID, UserID: l.UserID}
	if subject.Validate() != nil || !_adminOperationIDPattern.MatchString(l.OperationID) {
		return ErrDenied
	}
	return nil
}

// Validate verifies one adjustment receipt returned by the workload service.
func (a AdminAdjustment) Validate() error {
	if a.State != AdminAdjustmentDispatching && a.State != AdminAdjustmentApplied && a.State != AdminAdjustmentRejected && a.State != AdminAdjustmentUnknown {
		return ErrUnavailable
	}
	request := AdminAdjustRequest{OrganizationID: a.OrganizationID, UserID: a.UserID, OperationID: a.OperationID, Delta: a.Delta, ActorID: a.ActorID, Reason: a.Reason}
	if request.Validate() != nil {
		return ErrUnavailable
	}
	return nil
}

const _maxAdminExactInteger = int64(1<<53 - 1)

func validAdminAttribution(value string, maxBytes int) bool {
	return value != "" && len(value) <= maxBytes && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

func validReason(value string) bool {
	return value != "" && utf8.ValidString(value) && utf8.RuneCountInString(value) <= 200 && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

// AdminAdjust persists one adjustment intent and performs at most one upstream raw-quota write.
// AdminAdjust persists one adjustment intent and performs at most one upstream raw-quota write.
func (c *Client) AdminAdjust(ctx context.Context, request AdminAdjustRequest) (AdminAdjustment, error) {
	if request.Validate() != nil {
		return AdminAdjustment{}, ErrDenied
	}
	var result AdminAdjustment
	status, err := c.callPayloadStatus(ctx, AdminAdjustPath, request, &result, http.StatusOK, http.StatusAccepted)
	if err != nil {
		return AdminAdjustment{}, err
	}
	if !_validAdminAdjustResponse(status, result.State) || result.OperationID != request.OperationID || result.OrganizationID != request.OrganizationID || result.UserID != request.UserID || result.Delta != request.Delta || result.ActorID != request.ActorID || result.Reason != request.Reason {
		return AdminAdjustment{}, ErrUnavailable
	}
	return result, nil
}

// GetAdminAdjustment reads the durable receipt without dispatching another write.
func (c *Client) GetAdminAdjustment(ctx context.Context, lookup AdminAdjustLookup) (AdminAdjustment, error) {
	if lookup.Validate() != nil {
		return AdminAdjustment{}, ErrDenied
	}
	var result AdminAdjustment
	_, err := c.callPayloadStatus(ctx, AdminAdjustResultPath, lookup, &result, http.StatusOK)
	if err != nil {
		return AdminAdjustment{}, err
	}
	if result.OperationID != lookup.OperationID || result.OrganizationID != lookup.OrganizationID || result.UserID != lookup.UserID {
		return AdminAdjustment{}, ErrUnavailable
	}
	return result, nil
}

func _validAdminAdjustResponse(status int, state AdminAdjustmentState) bool {
	if status == http.StatusOK {
		return state == AdminAdjustmentApplied
	}
	if status == http.StatusAccepted {
		return state == AdminAdjustmentDispatching || state == AdminAdjustmentUnknown
	}
	return false
}

// UnmarshalJSON rejects duplicate, missing, unknown, or malformed adjustment request fields.
func (r *AdminAdjustRequest) UnmarshalJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return ErrDenied
	}
	seen := make(map[string]bool, 6)
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return ErrDenied
		}
		seen[name] = true
		switch name {
		case "organization_id":
			err = d.Decode(&r.OrganizationID)
		case "user_id":
			err = d.Decode(&r.UserID)
		case "operation_id":
			err = d.Decode(&r.OperationID)
		case "delta":
			err = d.Decode(&r.Delta)
		case "actor_id":
			err = d.Decode(&r.ActorID)
		case "reason":
			err = d.Decode(&r.Reason)
		default:
			return ErrDenied
		}
		if err != nil {
			return ErrDenied
		}
	}
	closing, err := d.Token()
	if err != nil || closing != json.Delim('}') || len(seen) != 6 {
		return ErrDenied
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return ErrDenied
	}
	return r.Validate()
}

// UnmarshalJSON rejects duplicate, missing, unknown, or malformed lookup fields.
func (l *AdminAdjustLookup) UnmarshalJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return ErrDenied
	}
	seen := make(map[string]bool, 3)
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return ErrDenied
		}
		seen[name] = true
		switch name {
		case "organization_id":
			err = d.Decode(&l.OrganizationID)
		case "user_id":
			err = d.Decode(&l.UserID)
		case "operation_id":
			err = d.Decode(&l.OperationID)
		default:
			return ErrDenied
		}
		if err != nil {
			return ErrDenied
		}
	}
	closing, err := d.Token()
	if err != nil || closing != json.Delim('}') || len(seen) != 3 {
		return ErrDenied
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return ErrDenied
	}
	return l.Validate()
}

// UnmarshalJSON rejects duplicate, missing, unknown, or malformed receipt fields.
func (a *AdminAdjustment) UnmarshalJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return ErrUnavailable
	}
	seen := make(map[string]bool, 7)
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return ErrUnavailable
		}
		seen[name] = true
		switch name {
		case "state":
			err = d.Decode(&a.State)
		case "operation_id":
			err = d.Decode(&a.OperationID)
		case "organization_id":
			err = d.Decode(&a.OrganizationID)
		case "user_id":
			err = d.Decode(&a.UserID)
		case "delta":
			err = d.Decode(&a.Delta)
		case "actor_id":
			err = d.Decode(&a.ActorID)
		case "reason":
			err = d.Decode(&a.Reason)
		default:
			return ErrUnavailable
		}
		if err != nil {
			return ErrUnavailable
		}
	}
	closing, err := d.Token()
	if err != nil || closing != json.Delim('}') || len(seen) != 7 {
		return ErrUnavailable
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return ErrUnavailable
	}
	return a.Validate()
}
