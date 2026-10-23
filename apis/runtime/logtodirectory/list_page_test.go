package logtodirectory

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// TestListPageMockProviderContractPendingInterop exercises the published client
// contract against an httptest provider. The real Logto handler and SDK/provider
// interop are intentionally pending and this test is not evidence of a live API.
func TestListPageMockProviderContractPendingInterop(t *testing.T) {
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == tokenPath {
			writeToken(response)
			return
		}
		if request.URL.Path != snapshotPath || request.Method != http.MethodPost {
			t.Errorf("request = %s %s, want POST %s", request.Method, request.URL.Path, snapshotPath)
		}
		fields := decodeRawObject(t, request)
		if len(fields) != 5 {
			t.Errorf("request fields = %v, want exactly five fields", fields)
		}
		assertRawJSON(t, fields, "organization_id", `"org-1"`)
		assertRawJSON(t, fields, "user_ids", `[]`)
		assertRawJSON(t, fields, "list_members", `true`)
		assertRawJSON(t, fields, "limit", `100`)
		assertRawJSON(t, fields, "include_departments", `false`)
		for _, forbidden := range []string{"cursor", "include_membership_epoch", "allow_member_listing"} {
			if _, exists := fields[forbidden]; exists {
				t.Errorf("forbidden request field %q present", forbidden)
			}
		}
		writeJSON(response, http.StatusOK, `{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user-1","name":"User One","avatar_url":"","permissions":[],"department_ids":[],"is_company_owner":false},{"user_id":"user-2","name":"User Two","avatar_url":"","permissions":[],"department_ids":[],"is_company_owner":false}],"departments":[],"next_cursor":"user-2"}`)
	}))
	snapshot, next, err := client.ListPage(context.Background(), "org-1", "", 0, Options{})
	if err != nil {
		t.Fatalf("ListPage() error = %v", err)
	}
	if next == nil || *next != "user-2" || len(snapshot.Members) != 2 {
		t.Fatalf("ListPage() next = %v, snapshot = %#v", next, snapshot)
	}
}

func TestListPageExplicitBoundsAndOptionalFields(t *testing.T) {
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == tokenPath {
			writeToken(response)
			return
		}
		fields := decodeRawObject(t, request)
		assertRawJSON(t, fields, "user_ids", `[]`)
		assertRawJSON(t, fields, "list_members", `true`)
		assertRawJSON(t, fields, "cursor", `"user-1"`)
		assertRawJSON(t, fields, "limit", `256`)
		assertRawJSON(t, fields, "include_departments", `true`)
		assertRawJSON(t, fields, "include_membership_epoch", `true`)
		writeJSON(response, http.StatusOK, `{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user-2","name":"User Two","avatar_url":"","permissions":[],"department_ids":["dept-1"],"is_company_owner":false,"membership_epoch":"9007199254740992"}],"departments":[{"id":"dept-1","name":"Team","parent_id":null}],"next_cursor":null}`)
	}))
	snapshot, next, err := client.ListPage(context.Background(), "org-1", "user-1", 256, Options{
		IncludeDepartments: true, IncludeMembershipEpoch: true,
	})
	if err != nil {
		t.Fatalf("ListPage() error = %v", err)
	}
	if next != nil {
		t.Fatalf("next = %q, want nil", *next)
	}
	if snapshot.Members[0].MembershipEpoch != "9007199254740992" || len(snapshot.Departments) != 1 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestListPageRejectsInvalidInputsBeforeHTTP(t *testing.T) {
	var calls atomic.Int32
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		http.Error(response, "unexpected", http.StatusInternalServerError)
	}))
	for _, test := range []struct {
		name           string
		organizationID string
		cursor         string
		limit          int
	}{
		{name: "empty organization", organizationID: "", limit: 1},
		{name: "oversize organization", organizationID: strings.Repeat("o", 22), limit: 1},
		{name: "negative limit", organizationID: "org-1", limit: -1},
		{name: "limit too large", organizationID: "org-1", limit: maxMembers + 1},
		{name: "oversize cursor", organizationID: "org-1", cursor: strings.Repeat("c", 129), limit: 1},
		{name: "control cursor", organizationID: "org-1", cursor: "cursor\x00one", limit: 1},
		{name: "whitespace cursor", organizationID: "org-1", cursor: " cursor ", limit: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := client.ListPage(context.Background(), test.organizationID, test.cursor, test.limit, Options{}); !errors.Is(err, ErrProtocol) {
				t.Fatalf("ListPage() error = %v, want ErrProtocol", err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("HTTP calls = %d, want 0", calls.Load())
	}
}

func TestListPageMandatoryNextCursorAndAdvanceRules(t *testing.T) {
	for _, test := range []struct {
		name       string
		cursor     string
		members    string
		nextCursor string
		want       *string
		wantErr    bool
	}{
		{name: "missing field", cursor: "b", nextCursor: "", wantErr: true},
		{name: "null", cursor: "b", nextCursor: `"next_cursor":null`, want: nil},
		{name: "empty string", cursor: "b", nextCursor: `"next_cursor":""`, wantErr: true},
		{name: "number", cursor: "b", nextCursor: `"next_cursor":2`, wantErr: true},
		{name: "boolean", cursor: "b", nextCursor: `"next_cursor":true`, wantErr: true},
		{name: "oversize", cursor: "b", nextCursor: `"next_cursor":"` + strings.Repeat("c", 129) + `"`, wantErr: true},
		{name: "control", cursor: "b", nextCursor: `"next_cursor":"c\u0000d"`, wantErr: true},
		{name: "not advancing", cursor: "b", nextCursor: `"next_cursor":"a"`, wantErr: true},
		{name: "not strictly advancing", cursor: "b", nextCursor: `"next_cursor":"b"`, wantErr: true},
		{name: "advancing empty page", cursor: "b", nextCursor: `"next_cursor":"c"`, want: stringPointer("c")},
		{name: "advancing with member", cursor: "b", members: `{"user_id":"c","name":"C","avatar_url":"","permissions":[],"department_ids":[],"is_company_owner":false}`, nextCursor: `"next_cursor":"c"`, want: stringPointer("c")},
		{name: "behind last member", cursor: "b", members: `{"user_id":"d","name":"D","avatar_url":"","permissions":[],"department_ids":[],"is_company_owner":false}`, nextCursor: `"next_cursor":"c"`, wantErr: true},
		{name: "ahead of last member", cursor: "b", members: `{"user_id":"c","name":"C","avatar_url":"","permissions":[],"department_ids":[],"is_company_owner":false}`, nextCursor: `"next_cursor":"d"`, want: stringPointer("d")},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			members := `[]`
			if test.members != "" {
				members = `[` + test.members + `]`
			}
			body := `{"organization":{"id":"org-1","name":"Company"},"members":` + members + `,"departments":[]`
			if test.nextCursor != "" {
				body += `,` + test.nextCursor
			}
			body += `}`
			client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path == tokenPath {
					writeToken(response)
					return
				}
				writeJSON(response, http.StatusOK, body)
			}))
			_, next, err := client.ListPage(context.Background(), "org-1", test.cursor, 100, Options{})
			if test.wantErr {
				if !errors.Is(err, ErrProtocol) {
					t.Fatalf("ListPage() error = %v, want ErrProtocol", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ListPage() error = %v", err)
			}
			if test.want == nil {
				if next != nil {
					t.Fatalf("next = %q, want nil", *next)
				}
				return
			}
			if next == nil || *next != *test.want {
				t.Fatalf("next = %v, want %q", next, *test.want)
			}
		})
	}
}

func TestListPageMemberOrderCountAndCursorBounds(t *testing.T) {
	for _, test := range []struct {
		name    string
		cursor  string
		limit   int
		members []string
		wantErr bool
	}{
		{name: "ordered after cursor", cursor: "a", limit: 2, members: []string{"b", "c"}},
		{name: "byte order", cursor: "", limit: 2, members: []string{"user-10", "user-2"}},
		{name: "descending", cursor: "", limit: 2, members: []string{"c", "b"}, wantErr: true},
		{name: "duplicate", cursor: "", limit: 2, members: []string{"b", "b"}, wantErr: true},
		{name: "member at cursor", cursor: "b", limit: 2, members: []string{"b", "c"}, wantErr: true},
		{name: "member before cursor", cursor: "b", limit: 2, members: []string{"a", "c"}, wantErr: true},
		{name: "count exceeds requested limit", cursor: "", limit: 1, members: []string{"a", "b"}, wantErr: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			body := listResponseWithMembers(test.members)
			client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path == tokenPath {
					writeToken(response)
					return
				}
				writeJSON(response, http.StatusOK, body)
			}))
			_, _, err := client.ListPage(context.Background(), "org-1", test.cursor, test.limit, Options{})
			if test.wantErr {
				if !errors.Is(err, ErrProtocol) {
					t.Fatalf("ListPage() error = %v, want ErrProtocol", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ListPage() error = %v", err)
			}
		})
	}

	members := make([]string, maxMembers+1)
	for index := range members {
		members[index] = fmt.Sprintf("user-%03d", index)
	}
	body := listResponseWithMembers(members)
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == tokenPath {
			writeToken(response)
			return
		}
		writeJSON(response, http.StatusOK, body)
	}))
	if _, _, err := client.ListPage(context.Background(), "org-1", "", maxMembers, Options{}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("257-member ListPage() error = %v, want ErrProtocol", err)
	}
}

func TestListPageStatusPolicyRegression(t *testing.T) {
	const sensitiveBody = "provider-only-sensitive-body"
	for _, test := range []struct {
		name   string
		status int
		want   error
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, want: ErrDenied},
		{name: "forbidden", status: http.StatusForbidden, want: ErrDenied},
		{name: "not found", status: http.StatusNotFound, want: ErrDenied},
		{name: "invalid request", status: http.StatusBadRequest, want: ErrProtocol},
		{name: "unavailable", status: http.StatusServiceUnavailable, want: ErrUnavailable},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			var tokenCalls, snapshotCalls atomic.Int32
			client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case tokenPath:
					tokenCalls.Add(1)
					writeToken(response)
				case snapshotPath:
					snapshotCalls.Add(1)
					writeJSON(response, test.status, `{"error":"`+sensitiveBody+`","access_token":"m2m-token"}`)
				default:
					http.NotFound(response, request)
				}
			}))
			_, _, err := client.ListPage(context.Background(), "org-1", "", 1, Options{})
			if !errors.Is(err, test.want) {
				t.Fatalf("ListPage() error = %v, want %v", err, test.want)
			}
			if tokenCalls.Load() != 1 || snapshotCalls.Load() != 1 {
				t.Fatalf("token calls = %d, snapshot calls = %d; want 1/1", tokenCalls.Load(), snapshotCalls.Load())
			}
			if strings.Contains(err.Error(), sensitiveBody) || strings.Contains(err.Error(), "m2m-token") {
				t.Fatalf("ListPage() exposed provider body or token: %v", err)
			}
		})
	}
}

func TestListPageDepartmentTreeValidation(t *testing.T) {
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == tokenPath {
			writeToken(response)
			return
		}
		fields := decodeRawObject(t, request)
		assertRawJSON(t, fields, "include_departments", `true`)
		writeJSON(response, http.StatusOK, `{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user-1","name":"User","avatar_url":"","permissions":[],"department_ids":["dept-1"],"is_company_owner":false}],"departments":[{"id":"dept-1","name":"Team","parent_id":"missing"}],"next_cursor":null}`)
	}))
	if _, _, err := client.ListPage(context.Background(), "org-1", "", 100, Options{IncludeDepartments: true}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("ListPage() error = %v, want ErrProtocol", err)
	}
}

func listResponseWithMembers(members []string) string {
	encoded := make([]string, 0, len(members))
	for _, member := range members {
		encoded = append(encoded, `{"user_id":"`+member+`","name":"User","avatar_url":"","permissions":[],"department_ids":[],"is_company_owner":false}`)
	}
	return `{"organization":{"id":"org-1","name":"Company"},"members":[` + strings.Join(encoded, ",") + `],"departments":[],"next_cursor":null}`
}

func stringPointer(value string) *string { return &value }
