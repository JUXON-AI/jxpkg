package identity

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestAuthorizationContextRoundTrip(t *testing.T) {
	want := Authorization{
		Member:              Member{OrganizationID: "org-a", UserID: "user-a"},
		IsOrganizationOwner: true,
		Departments: []Department{{
			ID:          "dept-a",
			AncestorIDs: []string{"dept-root", "dept-parent"},
		}},
		Permissions: []string{"agent.read", "agent.write"},
	}

	ctx := WithAuthorization(context.Background(), want)
	got, ok := AuthorizationFromContext(ctx)
	if !ok {
		t.Fatal("AuthorizationFromContext() did not find a valid authorization")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AuthorizationFromContext() = %#v, want %#v", got, want)
	}
	if !got.Allows("agent.read") {
		t.Fatal("Allows() rejected a granted permission")
	}
	if got.Allows("agent.delete") {
		t.Fatal("Allows() accepted a permission that was not granted")
	}
}

func TestAuthorizationContextRejectsInvalidIdentity(t *testing.T) {
	if _, ok := AuthorizationFromContext(nil); ok {
		t.Fatal("AuthorizationFromContext() accepted a nil context")
	}
	if _, ok := AuthorizationFromContext(context.Background()); ok {
		t.Fatal("AuthorizationFromContext() accepted a missing authorization")
	}

	valid := Authorization{
		Member:      Member{OrganizationID: "org-a", UserID: "user-a"},
		Permissions: []string{"agent.read"},
	}
	ctx := WithAuthorization(context.Background(), valid)

	tests := []struct {
		name  string
		value Authorization
	}{
		{
			name: "missing member organization",
			value: Authorization{
				Member: Member{UserID: "user-a"},
			},
		},
		{
			name: "empty department ID",
			value: Authorization{
				Member:      valid.Member,
				Departments: []Department{{}},
			},
		},
		{
			name: "empty ancestor ID",
			value: Authorization{
				Member:      valid.Member,
				Departments: []Department{{ID: "dept-a", AncestorIDs: []string{""}}},
			},
		},
		{
			name: "empty permission",
			value: Authorization{
				Member:      valid.Member,
				Permissions: []string{""},
			},
		},
		{
			name: "invalid UTF-8 permission",
			value: Authorization{
				Member:      valid.Member,
				Permissions: []string{string([]byte{0xff})},
			},
		},
		{
			name: "overlong permission",
			value: Authorization{
				Member:      valid.Member,
				Permissions: []string{strings.Repeat("a", maximumPermissionRunes+1)},
			},
		},
		{
			name: "permission with surrounding whitespace",
			value: Authorization{
				Member:      valid.Member,
				Permissions: []string{" agent.read"},
			},
		},
		{
			name: "permission with control character",
			value: Authorization{
				Member:      valid.Member,
				Permissions: []string{"agent\nread"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalidCtx := WithAuthorization(ctx, tt.value)
			if got, ok := AuthorizationFromContext(invalidCtx); ok {
				t.Fatalf("AuthorizationFromContext() accepted invalid authorization %#v", got)
			}
		})
	}
}

func TestAuthorizationContextKeepsOrganizationsSeparate(t *testing.T) {
	orgA := Authorization{
		Member:      Member{OrganizationID: "org-a", UserID: "same-native-name"},
		Permissions: []string{"org-a.read"},
	}
	orgB := Authorization{
		Member:      Member{OrganizationID: "org-b", UserID: "same-native-name"},
		Permissions: []string{"org-b.read"},
	}

	ctxA := WithAuthorization(context.Background(), orgA)
	ctxB := WithAuthorization(ctxA, orgB)

	gotA, ok := AuthorizationFromContext(ctxA)
	if !ok || !reflect.DeepEqual(gotA, orgA) {
		t.Fatalf("parent organization authorization = %#v, %v; want %#v, true", gotA, ok, orgA)
	}
	gotB, ok := AuthorizationFromContext(ctxB)
	if !ok || !reflect.DeepEqual(gotB, orgB) {
		t.Fatalf("child organization authorization = %#v, %v; want %#v, true", gotB, ok, orgB)
	}
}

func TestAuthorizationContextCopiesSlices(t *testing.T) {
	input := Authorization{
		Member: Member{OrganizationID: "org-a", UserID: "user-a"},
		Departments: []Department{{
			ID:          "dept-a",
			AncestorIDs: []string{"dept-root", "dept-parent"},
		}},
		Permissions: []string{"agent.read"},
	}
	ctx := WithAuthorization(context.Background(), input)

	input.Departments[0].ID = "mutated-dept"
	input.Departments[0].AncestorIDs[0] = "mutated-root"
	input.Permissions[0] = "mutated-permission"

	got, ok := AuthorizationFromContext(ctx)
	if !ok {
		t.Fatal("AuthorizationFromContext() did not find the stored authorization")
	}
	if got.Departments[0].ID != "dept-a" || got.Departments[0].AncestorIDs[0] != "dept-root" || got.Permissions[0] != "agent.read" {
		t.Fatalf("stored authorization changed through its input slices: %#v", got)
	}

	got.Departments[0].ID = "mutated-return"
	got.Departments[0].AncestorIDs[0] = "mutated-return-root"
	got.Permissions[0] = "mutated-return-permission"

	again, ok := AuthorizationFromContext(ctx)
	if !ok {
		t.Fatal("AuthorizationFromContext() did not find the stored authorization after return mutation")
	}
	if again.Departments[0].ID != "dept-a" || again.Departments[0].AncestorIDs[0] != "dept-root" || again.Permissions[0] != "agent.read" {
		t.Fatalf("stored authorization changed through a returned value: %#v", again)
	}
}

func TestAuthorizationContextPreservesSlicePresence(t *testing.T) {
	value := Authorization{
		Member:      Member{OrganizationID: "org-a", UserID: "user-a"},
		Departments: []Department{{ID: "dept-a", AncestorIDs: []string{}}},
		Permissions: []string{},
	}
	ctx := WithAuthorization(context.Background(), value)
	got, ok := AuthorizationFromContext(ctx)
	if !ok {
		t.Fatal("AuthorizationFromContext() did not find the stored authorization")
	}
	if got.Departments == nil || got.Departments[0].AncestorIDs == nil || got.Permissions == nil {
		t.Fatal("AuthorizationFromContext() changed non-nil empty slices to nil")
	}

	withoutSlices := value
	withoutSlices.Departments = nil
	withoutSlices.Permissions = nil
	got, ok = AuthorizationFromContext(WithAuthorization(context.Background(), withoutSlices))
	if !ok {
		t.Fatal("AuthorizationFromContext() did not find authorization with nil slices")
	}
	if got.Departments != nil || got.Permissions != nil {
		t.Fatal("AuthorizationFromContext() changed nil slices to non-nil")
	}
}

func TestAuthorizationAllowsDoesNotInferPermissions(t *testing.T) {
	value := Authorization{
		Member:              Member{OrganizationID: "org-a", UserID: "user-a"},
		IsOrganizationOwner: true,
		Permissions:         []string{"agent.read"},
	}
	if value.Allows("company:owner") {
		t.Fatal("Allows() inferred company:owner from IsOrganizationOwner")
	}
	if value.Allows("") {
		t.Fatal("Allows() accepted an empty permission")
	}
	if value.Allows("AGENT.READ") {
		t.Fatal("Allows() normalized or ignored case in a permission")
	}
	if (Authorization{}).Allows("agent.read") {
		t.Fatal("Allows() granted a permission for an invalid member")
	}
}

func TestMemberValidate(t *testing.T) {
	tests := []struct {
		name   string
		member Member
		valid  bool
	}{
		{name: "valid", member: Member{OrganizationID: "org-a", UserID: "user-a"}, valid: true},
		{name: "missing organization", member: Member{UserID: "user-a"}},
		{name: "invalid UTF-8", member: Member{OrganizationID: "org-a", UserID: string([]byte{0xff})}},
		{name: "overlong user ID", member: Member{OrganizationID: "org-a", UserID: strings.Repeat("a", 129)}},
		{name: "surrounding whitespace", member: Member{OrganizationID: " org-a", UserID: "user-a"}},
		{name: "control character", member: Member{OrganizationID: "org-a", UserID: "user\na"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.member.Validate()
			if tt.valid && err != nil {
				t.Fatalf("Member.Validate() error = %v", err)
			}
			if !tt.valid && !errors.Is(err, ErrInvalidMember) {
				t.Fatalf("Member.Validate() error = %v, want ErrInvalidMember", err)
			}
		})
	}
}
