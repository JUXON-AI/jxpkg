package logtodirectory

import (
	"errors"
	"net/http"
	"sync"
	"time"
)

var (
	// ErrDenied reports that the configured workload client, organization, or
	// requested member is not authorized for the directory operation.
	ErrDenied = errors.New("logtodirectory: denied")
	// ErrUnavailable reports a temporary transport, dependency, timeout, or
	// context failure. Callers may retry according to their own policy.
	ErrUnavailable = errors.New("logtodirectory: unavailable")
	// ErrProtocol reports invalid input or a response that violates the fixed
	// workload-directory protocol.
	ErrProtocol = errors.New("logtodirectory: protocol violation")
)

// Config configures a fixed Logto workload-directory client.
type Config struct {
	// Endpoint is the exact HTTPS Logto origin. It must not contain a path,
	// query, fragment, or user information.
	Endpoint string
	// ClientID is the dedicated Machine-to-Machine client identifier.
	ClientID string
	// ClientSecret is the dedicated Machine-to-Machine client secret. It is
	// never returned in errors or logged by this package.
	ClientSecret string
	// Resource is the dedicated read-only directory API resource indicator.
	Resource string
	// Timeout bounds each token or directory HTTP request. Zero uses ten
	// seconds; explicit values must be between one and thirty seconds.
	Timeout time.Duration
}

// Options selects optional snapshot fields.
type Options struct {
	// IncludeDepartments requests the organization's department tree and
	// validates member department references against it.
	IncludeDepartments bool
	// IncludeMembershipEpoch requires every returned member to carry a
	// canonical positive decimal membership epoch restricted to int64.
	IncludeMembershipEpoch bool
}

// Organization is the organization identity returned with a directory snapshot.
type Organization struct {
	// ID is the Logto organization identifier.
	ID string `json:"id"`
	// Name is the current organization display name.
	Name string `json:"name"`
}

// Member is one active workload-directory member.
type Member struct {
	// UserID is the current Logto user identifier.
	UserID string `json:"user_id"`
	// Name is the current user display name.
	Name string `json:"name"`
	// AvatarURL is an optional HTTPS avatar URL.
	AvatarURL string `json:"avatar_url"`
	// Permissions contains the provider-explicit permissions for the member.
	Permissions []string `json:"permissions"`
	// DepartmentIDs contains the member's direct departments, without
	// inferred ancestors.
	DepartmentIDs []string `json:"department_ids"`
	// IsCompanyOwner is the provider-explicit owner assertion. The client never
	// infers ownership from a global role.
	IsCompanyOwner bool `json:"is_company_owner"`
	// MembershipEpoch is a canonical positive decimal string when requested.
	// It remains absent from JSON when the option was not requested.
	MembershipEpoch string `json:"membership_epoch,omitempty"`
}

// Department is one node of the optional organization department tree.
type Department struct {
	// ID is the Logto department identifier.
	ID string `json:"id"`
	// Name is the current department display name.
	Name string `json:"name"`
	// ParentID is the current parent department; nil denotes a root department.
	ParentID *string `json:"parent_id"`
}

// Snapshot is one bounded workload-directory result.
type Snapshot struct {
	// Organization is the organization that owns the returned members.
	Organization Organization `json:"organization"`
	// Members contains only active members admitted by the provider.
	Members []Member `json:"members"`
	// Departments contains the requested department tree, or an empty slice.
	Departments []Department `json:"departments"`
}

// Client is a bounded workload-directory HTTP client. It caches only a short
// M2M access token; members, permissions, profiles, and departments are never
// cached.
type Client struct {
	config Config
	http   *http.Client
	now    func() time.Time

	tokenMu    sync.Mutex
	token      string
	tokenTill  time.Time
	refreshing *tokenRefresh
}

type tokenRefresh struct {
	done chan struct{}
	err  error
}
