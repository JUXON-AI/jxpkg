package logtodirectory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const validSnapshotBody = `{"organization":{"id":"org-1","name":"Company One"},"members":[{"user_id":"user-1","name":"User One","avatar_url":"https://images.example/user.png","permissions":["agent.create"],"department_ids":["dept-2"],"is_company_owner":true}],"departments":[{"id":"dept-1","name":"Root","parent_id":null},{"id":"dept-2","name":"Team","parent_id":"dept-1"}]}`

func TestSnapshotContractAndBoundedTokenCache(t *testing.T) {
	var tokenCalls, snapshotCalls atomic.Int32
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case tokenPath:
			tokenCalls.Add(1)
			if err := request.ParseForm(); err != nil {
				t.Errorf("ParseForm() error = %v", err)
			}
			assertFormValue(t, request, "grant_type", "client_credentials")
			assertFormValue(t, request, "client_id", "directory-client")
			assertFormValue(t, request, "client_secret", "private-client-secret")
			assertFormValue(t, request, "resource", "https://directory.example/api")
			assertFormValue(t, request, "scope", "directory:read")
			writeJSON(response, http.StatusOK, `{"access_token":"m2m-token","token_type":"Bearer","expires_in":3600,"scope":"directory:read"}`)
		case snapshotPath:
			snapshotCalls.Add(1)
			if request.Header.Get("Authorization") != "Bearer m2m-token" {
				t.Error("unexpected Authorization header")
			}
			fields := decodeRawObject(t, request)
			if len(fields) != 3 {
				t.Errorf("request fields = %v, want exactly three fields", fields)
			}
			assertRawJSON(t, fields, "organization_id", `"org-1"`)
			assertRawJSON(t, fields, "user_ids", `["user-1"]`)
			assertRawJSON(t, fields, "include_departments", `true`)
			if _, exists := fields["include_membership_epoch"]; exists {
				t.Errorf("include_membership_epoch unexpectedly present: %s", fields["include_membership_epoch"])
			}
			writeJSON(response, http.StatusOK, validSnapshotBody)
		default:
			http.NotFound(response, request)
		}
	}))

	for range 2 {
		snapshot, err := client.Snapshot(context.Background(), "org-1", []string{"user-1"}, Options{IncludeDepartments: true})
		if err != nil {
			t.Fatalf("Snapshot() error = %v", err)
		}
		if snapshot.Organization.ID != "org-1" || snapshot.Organization.Name != "Company One" || len(snapshot.Members) != 1 ||
			snapshot.Members[0].UserID != "user-1" || !snapshot.Members[0].IsCompanyOwner || len(snapshot.Departments) != 2 {
			t.Fatalf("Snapshot() = %#v", snapshot)
		}
	}
	if tokenCalls.Load() != 1 || snapshotCalls.Load() != 2 {
		t.Fatalf("token calls = %d, snapshot calls = %d; want 1/2", tokenCalls.Load(), snapshotCalls.Load())
	}
}

func TestSnapshotEncodesNilAndEmptyUserIDsAsArrays(t *testing.T) {
	for _, test := range []struct {
		name    string
		userIDs []string
	}{
		{name: "nil", userIDs: nil},
		{name: "empty", userIDs: []string{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path == tokenPath {
					writeToken(response)
					return
				}
				fields := decodeRawObject(t, request)
				if len(fields) != 3 {
					t.Errorf("request fields = %v, want exactly three fields", fields)
				}
				assertRawJSON(t, fields, "user_ids", `[]`)
				writeJSON(response, http.StatusOK, `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[]}`)
			}))
			snapshot, err := client.Snapshot(context.Background(), "org-1", test.userIDs, Options{})
			if err != nil {
				t.Fatalf("Snapshot() error = %v", err)
			}
			if snapshot.Members == nil || snapshot.Departments == nil || len(snapshot.Members) != 0 || len(snapshot.Departments) != 0 {
				t.Fatalf("empty arrays not normalized: %#v", snapshot)
			}
		})
	}
}

func TestSnapshotDoesNotInferCompanyOwnerFromPermission(t *testing.T) {
	client, _ := newPlainTestClient(t, directoryResponseHandler(
		`{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user-1","name":"User One","avatar_url":"","permissions":["company:owner"],"department_ids":[],"is_company_owner":false}],"departments":[]}`,
	))
	snapshot, err := client.Snapshot(context.Background(), "org-1", []string{"user-1"}, Options{})
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if snapshot.Members[0].IsCompanyOwner {
		t.Fatal("client inferred company owner from a permission name")
	}
}

func TestSnapshotRequiresCurrentCompanyOwnerWireField(t *testing.T) {
	tests := []struct {
		name    string
		owner   string
		wantErr bool
	}{
		{name: "current true", owner: `"is_company_owner":true`},
		{name: "current false", owner: `"is_company_owner":false`},
		{name: "missing", owner: "", wantErr: true},
		{name: "retired", owner: `"is_organization_owner":true`, wantErr: true},
		{name: "dual", owner: `"is_company_owner":true,"is_organization_owner":true`, wantErr: true},
		{name: "null current", owner: `"is_company_owner":null`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			member := `{"user_id":"user-1","name":"User","avatar_url":"","permissions":[],"department_ids":[]`
			if test.owner != "" {
				member += "," + test.owner
			}
			member += "}"
			body := `{"organization":{"id":"org-1","name":"Company"},"members":[` + member + `],"departments":[]}`
			client, _ := newPlainTestClient(t, directoryResponseHandler(body))
			snapshot, err := client.Snapshot(context.Background(), "org-1", []string{"user-1"}, Options{})
			if test.wantErr {
				if !errors.Is(err, ErrProtocol) {
					t.Fatalf("Snapshot() error = %v, want ErrProtocol", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Snapshot() error = %v", err)
			}
			wantOwner := test.name == "current true"
			if snapshot.Members[0].IsCompanyOwner != wantOwner {
				t.Fatalf("IsCompanyOwner = %t, want %t", snapshot.Members[0].IsCompanyOwner, wantOwner)
			}
		})
	}
}

func TestSnapshotAllowsMemberDepartmentsWithoutTree(t *testing.T) {
	client, _ := newPlainTestClient(t, directoryResponseHandler(
		`{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user-1","name":"User One","avatar_url":"","permissions":[],"department_ids":["dept-1"],"is_company_owner":false}],"departments":[]}`,
	))
	snapshot, err := client.Snapshot(context.Background(), "org-1", []string{"user-1"}, Options{})
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if got := snapshot.Members[0].DepartmentIDs; len(got) != 1 || got[0] != "dept-1" {
		t.Fatalf("DepartmentIDs = %#v", got)
	}
}

func TestNewClientValidatesConfigurationWithoutNetwork(t *testing.T) {
	valid := testConfig("https://logto.example")
	valid.Timeout = 0
	client, err := NewClient(valid)
	if err != nil {
		t.Fatalf("NewClient(valid) error = %v", err)
	}
	if client.http.Timeout != 10*time.Second {
		t.Fatalf("default timeout = %s, want 10s", client.http.Timeout)
	}

	for _, timeout := range []time.Duration{time.Second, 30 * time.Second} {
		config := testConfig("https://logto.example")
		config.Timeout = timeout
		client, err := NewClient(config)
		if err != nil || client.http.Timeout != timeout {
			t.Fatalf("NewClient(timeout=%s) error=%v", timeout, err)
		}
	}

	for _, test := range []struct {
		name   string
		change func(*Config)
	}{
		{name: "plaintext endpoint", change: func(config *Config) { config.Endpoint = "http://logto.example" }},
		{name: "endpoint path", change: func(config *Config) { config.Endpoint = "https://logto.example/tenant" }},
		{name: "endpoint query", change: func(config *Config) { config.Endpoint = "https://logto.example?tenant=1" }},
		{name: "empty client id", change: func(config *Config) { config.ClientID = "" }},
		{name: "control client id", change: func(config *Config) { config.ClientID = "client\x00id" }},
		{name: "oversize client id", change: func(config *Config) { config.ClientID = strings.Repeat("c", 129) }},
		{name: "empty secret", change: func(config *Config) { config.ClientSecret = "" }},
		{name: "control secret", change: func(config *Config) { config.ClientSecret = "secret\nsecret" }},
		{name: "oversize secret", change: func(config *Config) { config.ClientSecret = strings.Repeat("s", 4097) }},
		{name: "plaintext resource", change: func(config *Config) { config.Resource = "http://directory.example/api" }},
		{name: "resource query", change: func(config *Config) { config.Resource = "https://directory.example/api?audience=other" }},
		{name: "resource userinfo", change: func(config *Config) { config.Resource = "https://user@directory.example/api" }},
		{name: "short timeout", change: func(config *Config) { config.Timeout = 999 * time.Millisecond }},
		{name: "long timeout", change: func(config *Config) { config.Timeout = 31 * time.Second }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.change(&config)
			if _, err := NewClient(config); err == nil {
				t.Fatal("NewClient() error = nil")
			}
		})
	}
}

func TestSnapshotRejectsInvalidInputsBeforeHTTP(t *testing.T) {
	var calls atomic.Int32
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		http.Error(response, "unexpected", http.StatusInternalServerError)
	}))

	tooMany := make([]string, maxMembers+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("user-%03d", index)
	}
	for _, test := range []struct {
		name           string
		organizationID string
		userIDs        []string
	}{
		{name: "empty organization", organizationID: "", userIDs: []string{"user-1"}},
		{name: "oversize organization", organizationID: strings.Repeat("o", 22), userIDs: []string{"user-1"}},
		{name: "control organization", organizationID: "org\x00one", userIDs: []string{"user-1"}},
		{name: "duplicate user", organizationID: "org-1", userIDs: []string{"user-1", "user-1"}},
		{name: "oversize user", organizationID: "org-1", userIDs: []string{strings.Repeat("u", 129)}},
		{name: "control user", organizationID: "org-1", userIDs: []string{"user\x00one"}},
		{name: "too many users", organizationID: "org-1", userIDs: tooMany},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.Snapshot(context.Background(), test.organizationID, test.userIDs, Options{}); !errors.Is(err, ErrProtocol) {
				t.Fatalf("Snapshot() error = %v, want ErrProtocol", err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("HTTP calls = %d, want 0", calls.Load())
	}
}

func TestSnapshotRejectsInvalidResponses(t *testing.T) {
	permissions := make([]string, maxPermissions+1)
	for index := range permissions {
		permissions[index] = fmt.Sprintf("permission-%02d", index)
	}
	departmentIDs := make([]string, maxDirectDepartments+1)
	for index := range departmentIDs {
		departmentIDs[index] = fmt.Sprintf("dept-%03d", index)
	}
	tooManyDepartments := make([]string, 0, maxDepartments+1)
	for index := range maxDepartments + 1 {
		tooManyDepartments = append(tooManyDepartments, fmt.Sprintf(`{"id":"dept-%04d","name":"Department","parent_id":null}`, index))
	}

	for _, test := range []struct {
		name               string
		body               string
		includeDepartments bool
	}{
		{name: "organization mismatch", body: `{"organization":{"id":"org-2","name":"Other"},"members":[],"departments":[]}`},
		{name: "empty organization name", body: `{"organization":{"id":"org-1","name":""},"members":[],"departments":[]}`},
		{name: "extra member", body: `{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user-2","name":"Extra","avatar_url":"","permissions":[],"department_ids":[],"is_company_owner":false}],"departments":[]}`},
		{name: "empty member name", body: `{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user-1","name":"","avatar_url":"","permissions":[],"department_ids":[],"is_company_owner":false}],"departments":[]}`},
		{name: "null avatar", body: `{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user-1","name":"User","avatar_url":null,"permissions":[],"department_ids":[],"is_company_owner":false}],"departments":[]}`},
		{name: "null owner flag", body: `{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user-1","name":"User","avatar_url":"","permissions":[],"department_ids":[],"is_company_owner":null}],"departments":[]}`},
		{name: "duplicate member", body: `{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user-1","name":"User","avatar_url":"","permissions":[],"department_ids":[],"is_company_owner":false},{"user_id":"user-1","name":"User","avatar_url":"","permissions":[],"department_ids":[],"is_company_owner":false}],"departments":[]}`},
		{name: "oversize response member id", body: `{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"` + strings.Repeat("u", 129) + `","name":"User","avatar_url":"","permissions":[],"department_ids":[],"is_company_owner":false}],"departments":[]}`},
		{name: "control response member id", body: `{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user\u0000one","name":"User","avatar_url":"","permissions":[],"department_ids":[],"is_company_owner":false}],"departments":[]}`},
		{name: "null members", body: `{"organization":{"id":"org-1","name":"Company"},"members":null,"departments":[]}`},
		{name: "null permissions", body: `{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user-1","name":"User","avatar_url":"","permissions":null,"department_ids":[],"is_company_owner":false}],"departments":[]}`},
		{name: "wrong permissions type", body: `{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user-1","name":"User","avatar_url":"","permissions":"agent.create","department_ids":[],"is_company_owner":false}],"departments":[]}`},
		{name: "duplicate permission", body: memberWithLists(`["agent.create","agent.create"]`, `[]`)},
		{name: "too many permissions", body: memberWithLists(mustJSON(t, permissions), `[]`)},
		{name: "duplicate department id", body: memberWithLists(`[]`, `["dept-1","dept-1"]`)},
		{name: "too many direct departments", body: memberWithLists(`[]`, mustJSON(t, departmentIDs))},
		{name: "departments when not requested", body: `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[{"id":"dept-1","name":"Root","parent_id":null}]}`},
		{name: "null departments", body: `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":null}`},
		{name: "missing parent", body: `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[{"id":"dept-2","name":"Team","parent_id":"dept-1"}]}`, includeDepartments: true},
		{name: "self parent", body: `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[{"id":"dept-1","name":"Root","parent_id":"dept-1"}]}`, includeDepartments: true},
		{name: "cycle", body: `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[{"id":"dept-1","name":"Root","parent_id":"dept-2"},{"id":"dept-2","name":"Team","parent_id":"dept-1"}]}`, includeDepartments: true},
		{name: "duplicate tree department", body: `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[{"id":"dept-1","name":"Root","parent_id":null},{"id":"dept-1","name":"Other","parent_id":null}]}`, includeDepartments: true},
		{name: "numeric parent", body: `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[{"id":"dept-1","name":"Root","parent_id":1}]}`, includeDepartments: true},
		{name: "null department id", body: `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[{"id":null,"name":"Root","parent_id":null}]}`, includeDepartments: true},
		{name: "member department missing from tree", body: validSnapshotBodyWithoutParent(), includeDepartments: true},
		{name: "directory too large", body: `{"organization":{"id":"org-1","name":"Company"},"members":[],"departments":[` + strings.Join(tooManyDepartments, ",") + `]}`, includeDepartments: true},
		{name: "unknown field", body: `{"organization":{"id":"org-1","name":"Company","extra":true},"members":[],"departments":[]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, _ := newPlainTestClient(t, directoryResponseHandler(test.body))
			if _, err := client.Snapshot(context.Background(), "org-1", []string{"user-1"}, Options{IncludeDepartments: test.includeDepartments}); !errors.Is(err, ErrProtocol) {
				t.Fatalf("Snapshot() error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestSnapshotRejectsInvalidUTF8InMemberID(t *testing.T) {
	prefix := []byte(`{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user-`)
	suffix := []byte(`","name":"User","avatar_url":"","permissions":[],"department_ids":[],"is_company_owner":false}],"departments":[]}`)
	body := append(append(prefix, 0xff), suffix...)
	client, _ := newPlainTestClient(t, directoryResponseHandler(string(body)))
	if _, err := client.Snapshot(context.Background(), "org-1", []string{"user-�"}, Options{}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("Snapshot() error = %v, want ErrProtocol", err)
	}
}

func TestSnapshotMembershipEpochContract(t *testing.T) {
	for _, test := range []struct {
		name     string
		options  Options
		fragment string
		want     string
		wantErr  bool
	}{
		{name: "absent when opted out", options: Options{}, wantErr: false},
		{name: "null rejected when opted out", options: Options{}, fragment: `,"membership_epoch":null`, wantErr: true},
		{name: "value rejected when opted out", options: Options{}, fragment: `,"membership_epoch":"1"`, wantErr: true},
		{name: "absent rejected when opted in", options: Options{IncludeMembershipEpoch: true}, wantErr: true},
		{name: "null rejected when opted in", options: Options{IncludeMembershipEpoch: true}, fragment: `,"membership_epoch":null`, wantErr: true},
		{name: "number rejected when opted in", options: Options{IncludeMembershipEpoch: true}, fragment: `,"membership_epoch":9007199254740992`, wantErr: true},
		{name: "zero rejected", options: Options{IncludeMembershipEpoch: true}, fragment: `,"membership_epoch":"0"`, wantErr: true},
		{name: "leading zero rejected", options: Options{IncludeMembershipEpoch: true}, fragment: `,"membership_epoch":"01"`, wantErr: true},
		{name: "negative rejected", options: Options{IncludeMembershipEpoch: true}, fragment: `,"membership_epoch":"-1"`, wantErr: true},
		{name: "plus rejected", options: Options{IncludeMembershipEpoch: true}, fragment: `,"membership_epoch":"+1"`, wantErr: true},
		{name: "decimal rejected", options: Options{IncludeMembershipEpoch: true}, fragment: `,"membership_epoch":"1.0"`, wantErr: true},
		{name: "out of range rejected", options: Options{IncludeMembershipEpoch: true}, fragment: `,"membership_epoch":"9223372036854775808"`, wantErr: true},
		{name: "two to fifty three exact", options: Options{IncludeMembershipEpoch: true}, fragment: `,"membership_epoch":"9007199254740992"`, want: "9007199254740992"},
		{name: "max int64 exact", options: Options{IncludeMembershipEpoch: true}, fragment: `,"membership_epoch":"9223372036854775807"`, want: "9223372036854775807"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := epochMemberBody(test.fragment)
			client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path == tokenPath {
					writeToken(response)
					return
				}
				fields := decodeRawObject(t, request)
				if test.options.IncludeMembershipEpoch {
					if len(fields) != 4 {
						t.Errorf("request fields = %v, want exactly four fields", fields)
					}
					assertRawJSON(t, fields, "include_membership_epoch", `true`)
				} else {
					if len(fields) != 3 {
						t.Errorf("request fields = %v, want exactly three fields", fields)
					}
					if _, exists := fields["include_membership_epoch"]; exists {
						t.Error("include_membership_epoch present when opted out")
					}
				}
				writeJSON(response, http.StatusOK, body)
			}))
			snapshot, err := client.Snapshot(context.Background(), "org-1", []string{"user-1"}, test.options)
			if test.wantErr {
				if !errors.Is(err, ErrProtocol) {
					t.Fatalf("Snapshot() error = %v, want ErrProtocol", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Snapshot() error = %v", err)
			}
			if got := snapshot.Members[0].MembershipEpoch; got != test.want {
				t.Fatalf("MembershipEpoch = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSnapshotPreservesCancellationWithoutExposingTransportDetails(t *testing.T) {
	client, _ := newPlainTestClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Error(response, "private provider detail", http.StatusServiceUnavailable)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.Snapshot(ctx, "org-1", []string{"user-1"}, Options{})
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Snapshot() error = %v, want ErrUnavailable and context.Canceled", err)
	}
	if strings.Contains(err.Error(), "private provider detail") {
		t.Fatalf("error exposed response body: %v", err)
	}
}

func newPlainTestClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := newTestClient(testConfig(server.URL), server.Client().Transport)
	if err != nil {
		t.Fatalf("newTestClient() error = %v", err)
	}
	return client, server
}

func testConfig(endpoint string) Config {
	return Config{
		Endpoint: endpoint, ClientID: "directory-client", ClientSecret: "private-client-secret",
		Resource: "https://directory.example/api", Timeout: 5 * time.Second,
	}
}

func directoryResponseHandler(snapshotBody string) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == tokenPath {
			writeToken(response)
			return
		}
		writeJSON(response, http.StatusOK, snapshotBody)
	})
}

func writeToken(response http.ResponseWriter) {
	writeJSON(response, http.StatusOK, `{"access_token":"m2m-token","token_type":"Bearer","expires_in":3600,"scope":"directory:read"}`)
}

func writeJSON(response http.ResponseWriter, status int, body string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = io.WriteString(response, body)
}

func assertFormValue(t *testing.T, request *http.Request, key, want string) {
	t.Helper()
	if got := request.Form.Get(key); got != want {
		t.Errorf("form %s = %q, want %q", key, got, want)
	}
}

func decodeRawObject(t *testing.T, request *http.Request) map[string]json.RawMessage {
	t.Helper()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Errorf("ReadAll(request.Body) error = %v", err)
		return nil
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Errorf("Unmarshal(request body) error = %v; body=%s", err, body)
	}
	return fields
}

func assertRawJSON(t *testing.T, fields map[string]json.RawMessage, key, want string) {
	t.Helper()
	if got := strings.TrimSpace(string(fields[key])); got != want {
		t.Errorf("request field %s = %s, want %s", key, got, want)
	}
}

func memberWithLists(permissions, departmentIDs string) string {
	return `{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user-1","name":"User","avatar_url":"","permissions":` + permissions + `,"department_ids":` + departmentIDs + `,"is_company_owner":false}],"departments":[]}`
}

func validSnapshotBodyWithoutParent() string {
	return `{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user-1","name":"User","avatar_url":"","permissions":[],"department_ids":["dept-2"],"is_company_owner":false}],"departments":[{"id":"dept-2","name":"Team","parent_id":"dept-1"}]}`
}

func epochMemberBody(epochFragment string) string {
	return `{"organization":{"id":"org-1","name":"Company"},"members":[{"user_id":"user-1","name":"User","avatar_url":"","permissions":[],"department_ids":[],"is_company_owner":false` + epochFragment + `}],"departments":[]}`
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return string(document)
}
