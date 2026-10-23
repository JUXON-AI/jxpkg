package credits

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/JUXON-AI/jxpkg/identity"
)

func TestMembershipSubjectHasNoNumericIdentityFallback(t *testing.T) {
	typ := reflect.TypeOf(Subject{})
	for _, name := range []string{"CompanyID", "UIN", "Issuer"} {
		if _, ok := typ.FieldByName(name); ok {
			t.Errorf("obsolete business identity field remains: %s", name)
		}
	}
}

func TestMembershipSubjectValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		org  string
		user string
		ok   bool
	}{
		{"valid", "org-a", "user", true},
		{"maximum", strings.Repeat("o", 64), strings.Repeat("u", 128), true},
		{"unicode characters", "org-a", strings.Repeat("用", 128), true},
		{"missing organization", "", "user", false},
		{"missing user", "org-a", "", false},
		{"long organization", strings.Repeat("o", 65), "user", false},
		{"long user", "org-a", strings.Repeat("u", 129), false},
		{"leading space", "org-a", " user", false},
		{"trailing space", "org-a ", "user", false},
		{"control", "org-a", "user\x00other", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := json.Marshal(map[string]string{"organization_id": tc.org, "user_id": tc.user})
			if err != nil {
				t.Fatal(err)
			}
			var subject Subject
			if err := json.Unmarshal(wire, &subject); err != nil {
				t.Fatal(err)
			}
			value, err := NewExecution(subject, func(context.Context, Subject) (Connection, error) {
				return Connection{}, ErrUnavailable
			})
			if tc.ok {
				if err != nil || value.Subject() != subject {
					t.Fatal("valid complete membership was not retained")
				}
				return
			}
			if !errors.Is(err, ErrDenied) || value != nil {
				t.Fatal("invalid membership accepted")
			}
		})
	}
}

func TestSubjectRejectsInvalidUTF8WithoutNormalization(t *testing.T) {
	for _, subject := range []Subject{
		{OrganizationID: "org-a", UserID: string([]byte{0xff})},
		{OrganizationID: string([]byte{0xff}), UserID: "user-a"},
	} {
		if !errors.Is(subject.Validate(), identity.ErrInvalidMember) {
			t.Fatal("invalid UTF-8 identity accepted")
		}
	}
}
