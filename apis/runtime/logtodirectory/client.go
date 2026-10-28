package logtodirectory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/JUXON-AI/jxpkg/requestid"
)

const (
	tokenPath          = "/oidc/token"
	snapshotPath       = "/api/workload-directory/snapshot"
	_organizationsPath = "/api/workload-directory/organizations"
	directoryScope     = "directory:read"

	_organizationDeniedBody = `{"error":"organization_access_denied"}`

	defaultTimeout = 10 * time.Second
	minTimeout     = time.Second
	maxTimeout     = 30 * time.Second

	maxOrganizationIDRunes     = 21
	_maxOrganizationQueryRunes = 128
	maxMemberIDRunes           = 128
	maxDepartmentIDRunes       = 21
	maxPermissionRunes         = 256
	maxClientIDRunes           = 128
	maxSecretBytes             = 4096
	maxTokenRunes              = 32768
	maxMembers                 = 256
	_maxOrganizations          = 100
	maxDepartments             = 1000
	maxDirectDepartments       = 100
	maxPermissions             = 32
	maxRequestBytes            = 32 << 10
	maxTokenBodyBytes          = 64 << 10
	maxSnapshotBodyBytes       = 4 << 20
	_maxErrorBodyBytes         = 256
	maxTokenLifetime           = int64(3600)
	tokenExpirySkew            = 30 * time.Second
)

type snapshotRequest struct {
	OrganizationID         string   `json:"organization_id"`
	UserIDs                []string `json:"user_ids"`
	IncludeDepartments     bool     `json:"include_departments"`
	IncludeMembershipEpoch bool     `json:"include_membership_epoch,omitempty"`
}

type listPageRequest struct {
	OrganizationID         string   `json:"organization_id"`
	UserIDs                []string `json:"user_ids"`
	ListMembers            bool     `json:"list_members"`
	Cursor                 string   `json:"cursor,omitempty"`
	Limit                  int      `json:"limit"`
	IncludeDepartments     bool     `json:"include_departments"`
	IncludeMembershipEpoch bool     `json:"include_membership_epoch,omitempty"`
}

type organizationSearchRequest struct {
	Query  string `json:"query"`
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit"`
}

type tokenResponse struct {
	AccessToken *string         `json:"access_token"`
	TokenType   *string         `json:"token_type"`
	ExpiresIn   *int64          `json:"expires_in"`
	Scope       json.RawMessage `json:"scope"`
}

// NewClient validates config and creates a fixed-origin Logto workload
// directory client. Construction performs no network, environment, or database
// access.
func NewClient(config Config) (*Client, error) {
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, ErrUnavailable
	}
	transport := defaultTransport.Clone()
	transport.Proxy = nil
	return NewClientWithTransport(config, transport)
}

// NewClientWithTransport creates a fixed-origin HTTPS client with an explicit
// startup-injected transport. The caller owns that trusted dependency and any
// connection policy it applies; request callers cannot replace it.
func NewClientWithTransport(config Config, transport http.RoundTripper) (*Client, error) {
	return newClient(config, transport, false)
}

// newTestClient is the unexported plaintext-HTTP seam used only by same-package
// tests with an httptest server. Production callers cannot enable plaintext.
func newTestClient(config Config, transport http.RoundTripper) (*Client, error) {
	return newClient(config, transport, true)
}

func newClient(config Config, transport http.RoundTripper, allowPlainHTTP bool) (*Client, error) {
	if transport == nil || !validOrigin(config.Endpoint, allowPlainHTTP) ||
		!canonicalValue(config.ClientID, maxClientIDRunes) || !validSecret(config.ClientSecret) ||
		!validResource(config.Resource) {
		return nil, ErrUnavailable
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.Timeout < minTimeout || config.Timeout > maxTimeout {
		return nil, ErrUnavailable
	}
	return &Client{
		config: config,
		http: &http.Client{
			Timeout:   config.Timeout,
			Transport: &boundedTransport{base: transport, origin: config.Endpoint},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now: time.Now,
	}, nil
}

// Close releases idle HTTP connections held by the client. It does not cancel
// in-flight requests or invalidate cached credentials.
func (client *Client) Close() error {
	if client != nil && client.http != nil {
		client.http.CloseIdleConnections()
	}
	return nil
}

// Snapshot reads one online snapshot for organizationID and the optional
// userIDs subset. A nil or empty subset is sent as [] and returns organization
// metadata with no members. Member, permission, profile, and department data
// are never cached by the client.
func (client *Client) Snapshot(ctx context.Context, organizationID string, userIDs []string, options Options) (Snapshot, error) {
	if !client.ready(ctx) {
		return Snapshot{}, ErrUnavailable
	}
	if !canonicalValue(organizationID, maxOrganizationIDRunes) || len(userIDs) > maxMembers {
		return Snapshot{}, ErrProtocol
	}
	requested := make(map[string]struct{}, len(userIDs))
	for _, userID := range userIDs {
		if !canonicalValue(userID, maxMemberIDRunes) {
			return Snapshot{}, ErrProtocol
		}
		if _, duplicate := requested[userID]; duplicate {
			return Snapshot{}, ErrProtocol
		}
		requested[userID] = struct{}{}
	}
	body, err := json.Marshal(snapshotRequest{
		OrganizationID:         organizationID,
		UserIDs:                append([]string{}, userIDs...),
		IncludeDepartments:     options.IncludeDepartments,
		IncludeMembershipEpoch: options.IncludeMembershipEpoch,
	})
	if err != nil {
		return Snapshot{}, ErrUnavailable
	}
	if len(body) > maxRequestBytes {
		return Snapshot{}, ErrProtocol
	}
	token, err := client.accessToken(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	document, err := client.postSnapshot(ctx, token, body)
	if err != nil {
		return Snapshot{}, err
	}
	var response wireSnapshot
	if err := strictJSON(document, &response); err != nil {
		return Snapshot{}, ErrProtocol
	}
	return validateSnapshot(response, snapshotValidation{
		organizationID: organizationID,
		requested:      requested,
		options:        options,
	})
}

// ListPage reads one bounded provider page from the same snapshot endpoint.
// The provider registry must explicitly enable member listing. A zero limit
// defaults to 100. The returned cursor is nil only for an explicit JSON null.
func (client *Client) ListPage(ctx context.Context, organizationID, cursor string, limit int, options Options) (Snapshot, *string, error) {
	if !client.ready(ctx) {
		return Snapshot{}, nil, ErrUnavailable
	}
	if !canonicalValue(organizationID, maxOrganizationIDRunes) {
		return Snapshot{}, nil, ErrProtocol
	}
	if cursor != "" && !canonicalValue(cursor, maxMemberIDRunes) {
		return Snapshot{}, nil, ErrProtocol
	}
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > maxMembers {
		return Snapshot{}, nil, ErrProtocol
	}
	body, err := json.Marshal(listPageRequest{
		OrganizationID:         organizationID,
		UserIDs:                []string{},
		ListMembers:            true,
		Cursor:                 cursor,
		Limit:                  limit,
		IncludeDepartments:     options.IncludeDepartments,
		IncludeMembershipEpoch: options.IncludeMembershipEpoch,
	})
	if err != nil {
		return Snapshot{}, nil, ErrUnavailable
	}
	if len(body) > maxRequestBytes {
		return Snapshot{}, nil, ErrProtocol
	}
	token, err := client.accessToken(ctx)
	if err != nil {
		return Snapshot{}, nil, err
	}
	document, err := client.postSnapshot(ctx, token, body)
	if err != nil {
		return Snapshot{}, nil, err
	}
	var response wireListPage
	if err := strictJSON(document, &response); err != nil {
		return Snapshot{}, nil, ErrProtocol
	}
	nextCursor, err := parseNextCursor(response.NextCursor)
	if err != nil || (nextCursor != nil && cursor != "" && *nextCursor <= cursor) {
		return Snapshot{}, nil, ErrProtocol
	}
	snapshot, err := validateSnapshot(response.snapshot(), snapshotValidation{
		organizationID: organizationID,
		listMode:       true,
		cursor:         cursor,
		limit:          limit,
		options:        options,
	})
	if err != nil {
		return Snapshot{}, nil, err
	}
	if nextCursor != nil && len(snapshot.Members) > 0 && *nextCursor < snapshot.Members[len(snapshot.Members)-1].UserID {
		return Snapshot{}, nil, ErrProtocol
	}
	return snapshot, nextCursor, nil
}

// SearchOrganizations reads one bounded page of organizations admitted to the
// configured workload client. A nil cursor omits the provider cursor; the same
// absence in the response means the page is terminal.
func (client *Client) SearchOrganizations(ctx context.Context, query, cursor string, limit int) ([]Organization, *string, error) {
	if !client.ready(ctx) {
		return nil, nil, ErrUnavailable
	}
	if !validOrganizationQuery(query) || limit < 1 || limit > _maxOrganizations ||
		(cursor != "" && !validOrganizationID(cursor)) {
		return nil, nil, ErrProtocol
	}
	body, err := json.Marshal(organizationSearchRequest{Query: query, Cursor: cursor, Limit: limit})
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	if len(body) > maxRequestBytes {
		return nil, nil, ErrProtocol
	}
	token, err := client.accessToken(ctx)
	if err != nil {
		return nil, nil, err
	}
	document, err := client.postDirectory(ctx, _organizationsPath, token, body)
	if err != nil {
		return nil, nil, err
	}
	var response wireOrganizationSearch
	if err := strictJSON(document, &response); err != nil {
		return nil, nil, ErrProtocol
	}
	nextCursor, err := parseOptionalOrganizationCursor(response.NextCursor)
	if err != nil {
		return nil, nil, ErrProtocol
	}
	organizations, err := validateOrganizationSearch(response.Organizations, cursor, nextCursor, limit)
	if err != nil {
		return nil, nil, err
	}
	return organizations, nextCursor, nil
}

func (client *Client) ready(ctx context.Context) bool {
	return client != nil && client.http != nil && client.now != nil && ctx != nil
}

func (client *Client) postSnapshot(ctx context.Context, token string, body []byte) ([]byte, error) {
	return client.postDirectory(ctx, snapshotPath, token, body)
}

func (client *Client) postDirectory(ctx context.Context, path, token string, body []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.config.Endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, ErrUnavailable
	}
	setNoStoreHeaders(request)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		return nil, requestFailure(ctx, err)
	}
	defer response.Body.Close()
	if err := classifyDirectoryResponse(response); err != nil {
		return nil, err
	}
	return readJSONResponse(ctx, response, maxSnapshotBodyBytes)
}

func (client *Client) accessToken(ctx context.Context) (string, error) {
	now := client.now()
	client.tokenMu.Lock()
	if client.token != "" && now.Before(client.tokenTill) {
		token := client.token
		client.tokenMu.Unlock()
		return token, nil
	}
	if refresh := client.refreshing; refresh != nil {
		client.tokenMu.Unlock()
		select {
		case <-refresh.done:
			client.tokenMu.Lock()
			token := client.token
			tokenTill := client.tokenTill
			refreshErr := refresh.err
			client.tokenMu.Unlock()
			if token != "" && client.now().Before(tokenTill) {
				return token, nil
			}
			if refreshErr != nil {
				return "", refreshErr
			}
			return client.accessToken(ctx)
		case <-ctx.Done():
			return "", wrapContextFailure(ctx.Err())
		}
	}
	refresh := &tokenRefresh{done: make(chan struct{})}
	client.refreshing = refresh
	client.token = ""
	client.tokenTill = time.Time{}
	client.tokenMu.Unlock()

	tokenStartedAt := client.now()
	token, lifetime, err := client.fetchToken(ctx)
	tokenCompletedAt := client.now()

	client.tokenMu.Lock()
	if err == nil {
		skew := tokenExpirySkew
		if lifetime <= 2*skew {
			skew = lifetime / 2
		}
		tokenTill := tokenStartedAt.Add(lifetime - skew)
		if !tokenCompletedAt.Before(tokenTill) {
			err = ErrUnavailable
		} else {
			client.token = token
			client.tokenTill = tokenTill
		}
	}
	refresh.err = err
	client.refreshing = nil
	close(refresh.done)
	token = client.token
	client.tokenMu.Unlock()
	if err != nil {
		return "", err
	}
	return token, nil
}

func (client *Client) fetchToken(ctx context.Context) (string, time.Duration, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", client.config.ClientID)
	form.Set("client_secret", client.config.ClientSecret)
	form.Set("resource", client.config.Resource)
	form.Set("scope", directoryScope)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.config.Endpoint+tokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, ErrUnavailable
	}
	setNoStoreHeaders(request)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.http.Do(request)
	if err != nil {
		return "", 0, requestFailure(ctx, err)
	}
	defer response.Body.Close()
	if err := classifyStatus(response.StatusCode, true); err != nil {
		return "", 0, err
	}
	document, err := readJSONResponse(ctx, response, maxTokenBodyBytes)
	if err != nil {
		return "", 0, err
	}
	var token tokenResponse
	if err := strictJSON(document, &token); err != nil || token.AccessToken == nil || token.TokenType == nil ||
		token.ExpiresIn == nil {
		return "", 0, ErrProtocol
	}
	scope, err := parseOptionalString(token.Scope)
	if err != nil || !canonicalValue(*token.AccessToken, maxTokenRunes) ||
		!strings.EqualFold(*token.TokenType, "bearer") || *token.ExpiresIn <= 0 || *token.ExpiresIn > maxTokenLifetime ||
		!tokenScopeAllowsDirectory(scope) {
		return "", 0, ErrProtocol
	}
	return *token.AccessToken, time.Duration(*token.ExpiresIn) * time.Second, nil
}

func tokenScopeAllowsDirectory(scope string) bool {
	if scope == "" {
		return true
	}
	for _, value := range strings.Fields(scope) {
		if value == directoryScope {
			return true
		}
	}
	return false
}

func setNoStoreHeaders(request *http.Request) {
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Pragma", "no-cache")
}

func classifyStatus(status int, tokenRequest bool) error {
	if tokenRequest {
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			return ErrDenied
		}
	} else if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound {
		return ErrDenied
	}
	if status == http.StatusOK {
		return nil
	}
	if status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests ||
		status >= http.StatusInternalServerError {
		return ErrUnavailable
	}
	return ErrProtocol
}

func classifyDirectoryResponse(response *http.Response) error {
	if response == nil {
		return ErrProtocol
	}
	if response.StatusCode != http.StatusForbidden {
		return classifyStatus(response.StatusCode, false)
	}
	if organizationAccessDenied(response) {
		return ErrOrganizationDenied
	}
	return ErrDenied
}

func organizationAccessDenied(response *http.Response) bool {
	if response.Body == nil || response.ContentLength > _maxErrorBodyBytes {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return false
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, _maxErrorBodyBytes+1))
	return err == nil && bytes.Equal(document, []byte(_organizationDeniedBody))
}

func readJSONResponse(ctx context.Context, response *http.Response, limit int64) ([]byte, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, wrapContextFailure(ctx.Err())
	}
	if response == nil || response.Body == nil || response.ContentLength > limit {
		return nil, ErrProtocol
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, ErrProtocol
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			return nil, wrapContextFailure(ctx.Err())
		}
		if errors.Is(err, context.Canceled) {
			return nil, wrapContextFailure(context.Canceled)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, wrapContextFailure(context.DeadlineExceeded)
		}
		return nil, ErrProtocol
	}
	if int64(len(document)) > limit {
		return nil, ErrProtocol
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, wrapContextFailure(ctx.Err())
	}
	return document, nil
}

func requestFailure(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return wrapContextFailure(ctx.Err())
	}
	if errors.Is(err, context.Canceled) {
		return wrapContextFailure(context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return wrapContextFailure(context.DeadlineExceeded)
	}
	return ErrUnavailable
}

func wrapContextFailure(cause error) error {
	return fmt.Errorf("%w: %w", ErrUnavailable, cause)
}

func validSecret(value string) bool {
	if value == "" || len(value) > maxSecretBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validResource(value string) bool {
	if len(value) > 2048 {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}

func validOrigin(value string, allowPlainHTTP bool) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" ||
		parsed.ForceQuery || parsed.Fragment != "" || parsed.String() != value {
		return false
	}
	return parsed.Scheme == "https" || (allowPlainHTTP && parsed.Scheme == "http")
}

type boundedTransport struct {
	base   http.RoundTripper
	origin string
}

func (transport *boundedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport == nil || transport.base == nil || request == nil || request.URL == nil ||
		request.Method != http.MethodPost || request.URL.Scheme+"://"+request.URL.Host != transport.origin ||
		(request.URL.Path != tokenPath && request.URL.Path != snapshotPath && request.URL.Path != _organizationsPath) ||
		request.URL.RawQuery != "" {
		return nil, errors.New("logtodirectory: unregistered endpoint")
	}
	clone := request.Clone(request.Context())
	if id := requestid.FromContext(request.Context()); id != "" {
		clone.Header.Set("X-Request-Id", id)
	}
	return transport.base.RoundTrip(clone)
}

func (transport *boundedTransport) CloseIdleConnections() {
	if transport == nil || transport.base == nil {
		return
	}
	if closer, ok := transport.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func canonicalValue(value string, limit int) bool {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > limit || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func displayValue(value string, limit int, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
	}
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > limit {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) && character != '\t' {
			return false
		}
	}
	return true
}

func validOrganizationName(value string) bool {
	const maxOrganizationNameRunes = 128
	return value != "" && utf8.ValidString(value) && utf8.RuneCountInString(value) <= maxOrganizationNameRunes
}

func validOrganizationQuery(value string) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > _maxOrganizationQueryRunes {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validOrganizationID(value string) bool {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxOrganizationIDRunes {
		return false
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) || character == '\ufeff' {
			return false
		}
	}
	return true
}

func validAvatar(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 2048 {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == ""
}
