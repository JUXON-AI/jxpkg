package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDisplayNamesValidate(t *testing.T) {
	tests := []struct {
		name  string
		value DisplayNames
		valid bool
	}{
		{name: "valid", value: DisplayNames{Username: "user-a", OrganizationName: "Company A"}, valid: true},
		{name: "unicode", value: DisplayNames{Username: "用户甲", OrganizationName: "甲公司"}, valid: true},
		{name: "maximum bytes", value: DisplayNames{Username: strings.Repeat("u", 512), OrganizationName: strings.Repeat("o", 512)}, valid: true},
		{name: "missing username", value: DisplayNames{OrganizationName: "Company A"}},
		{name: "missing organization", value: DisplayNames{Username: "user-a"}},
		{name: "blank username", value: DisplayNames{Username: " \t", OrganizationName: "Company A"}},
		{name: "blank organization", value: DisplayNames{Username: "user-a", OrganizationName: "\n "}},
		{name: "invalid username UTF-8", value: DisplayNames{Username: string([]byte{0xff}), OrganizationName: "Company A"}},
		{name: "control organization", value: DisplayNames{Username: "user-a", OrganizationName: "Company\x00A"}},
		{name: "leading control username", value: DisplayNames{Username: "\tuser-a", OrganizationName: "Company A"}},
		{name: "trailing control organization", value: DisplayNames{Username: "user-a", OrganizationName: "Company A\n"}},
		{name: "username over byte limit", value: DisplayNames{Username: strings.Repeat("用", 171), OrganizationName: "Company A"}},
		{name: "organization over byte limit", value: DisplayNames{Username: "user-a", OrganizationName: strings.Repeat("司", 171)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.value.Validate()
			if tt.valid && err != nil {
				t.Fatalf("DisplayNames.Validate() error = %v", err)
			}
			if !tt.valid && err == nil {
				t.Fatal("DisplayNames.Validate() accepted invalid display names")
			}
		})
	}
}

func TestDisplayNamesUnmarshalJSONRejectsAmbiguousObjects(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		valid bool
	}{
		{name: "valid", raw: `{"username":"user-a","organization_name":"Company A"}`, valid: true},
		{name: "valid reversed", raw: `{"organization_name":"Company A","username":"user-a"}`, valid: true},
		{name: "unknown", raw: `{"username":"user-a","organization_name":"Company A","role":"admin"}`},
		{name: "case alias", raw: `{"Username":"user-a","organization_name":"Company A"}`},
		{name: "duplicate username", raw: `{"username":"user-a","username":"user-b","organization_name":"Company A"}`},
		{name: "duplicate organization", raw: `{"username":"user-a","organization_name":"Company A","organization_name":"Company B"}`},
		{name: "null object", raw: `null`},
		{name: "null username", raw: `{"username":null,"organization_name":"Company A"}`},
		{name: "null organization", raw: `{"username":"user-a","organization_name":null}`},
		{name: "numeric username", raw: `{"username":1,"organization_name":"Company A"}`},
		{name: "object organization", raw: `{"username":"user-a","organization_name":{}}`},
		{name: "missing username", raw: `{"organization_name":"Company A"}`},
		{name: "missing organization", raw: `{"username":"user-a"}`},
		{name: "trailing value", raw: `{"username":"user-a","organization_name":"Company A"}{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got DisplayNames
			err := json.Unmarshal([]byte(tt.raw), &got)
			if tt.valid {
				if err != nil || got != (DisplayNames{Username: "user-a", OrganizationName: "Company A"}) {
					t.Fatalf("json.Unmarshal() = %#v, %v", got, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("json.Unmarshal() accepted ambiguous object: %#v", got)
			}
		})
	}
}

func TestDisplayNamesUnmarshalJSONRejectsInvalidUTF8(t *testing.T) {
	raw := append([]byte(`{"username":"`), 0xff)
	raw = append(raw, []byte(`","organization_name":"Company A"}`)...)
	var got DisplayNames
	if err := json.Unmarshal(raw, &got); err == nil {
		t.Fatalf("json.Unmarshal() accepted invalid UTF-8: %#v", got)
	}
}

func TestDisplayNamesContextTrimsAndCannotCrossSubjects(t *testing.T) {
	member := Member{OrganizationID: "org-a", UserID: "user-a"}
	ctx, err := WithDisplayNames(context.Background(), member, DisplayNames{
		Username:         "  user-a  ",
		OrganizationName: "  Company A  ",
	})
	if err != nil {
		t.Fatal(err)
	}

	got, ok := DisplayNamesFromContext(ctx, member)
	if !ok || got.Username != "user-a" || got.OrganizationName != "Company A" {
		t.Fatalf("DisplayNamesFromContext() = %#v, %v", got, ok)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"username":"user-a","organization_name":"Company A"}` {
		t.Fatalf("display names JSON = %s", raw)
	}
	if _, ok := AuthorizationFromContext(ctx); ok {
		t.Fatal("display names created authorization")
	}

	for _, other := range []Member{
		{OrganizationID: "org-b", UserID: "user-a"},
		{OrganizationID: "org-a", UserID: "user-b"},
		{},
	} {
		if value, ok := DisplayNamesFromContext(ctx, other); ok || value != (DisplayNames{}) {
			t.Fatalf("display names reused for subject %#v: %#v, %v", other, value, ok)
		}
	}
	if value, ok := DisplayNamesFromContext(nil, member); ok || value != (DisplayNames{}) {
		t.Fatalf("nil context returned display names: %#v, %v", value, ok)
	}
}

func TestWithDisplayNamesRejectsInvalidInputWithoutReplacingContext(t *testing.T) {
	if _, err := WithDisplayNames(context.Background(), Member{}, DisplayNames{}); !errors.Is(err, ErrInvalidMember) {
		t.Fatalf("invalid member did not fail first: %v", err)
	}
	member := Member{OrganizationID: "org-a", UserID: "user-a"}
	ctx, err := WithDisplayNames(context.Background(), member, DisplayNames{Username: "user-a", OrganizationName: "Company A"})
	if err != nil {
		t.Fatal(err)
	}
	if invalid, err := WithDisplayNames(ctx, member, DisplayNames{Username: "forged", OrganizationName: " "}); err == nil || invalid != ctx {
		t.Fatalf("invalid display names = %#v, %v", invalid, err)
	}
	got, ok := DisplayNamesFromContext(ctx, member)
	if !ok || got.Username != "user-a" || got.OrganizationName != "Company A" {
		t.Fatalf("original display names changed: %#v, %v", got, ok)
	}
}
