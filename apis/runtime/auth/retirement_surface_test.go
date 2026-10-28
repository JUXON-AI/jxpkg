package auth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyNumericIdentitySurfaceIsRetired(t *testing.T) {
	forbidden := map[string]struct{}{
		"AuthBearer":                           {},
		"AuthMode":                             {},
		"AuthorizationContextResolveRequest":   {},
		"AuthorizationContextResolveResponse":  {},
		"AuthorizationContextResolver":         {},
		"AuthorizationDepartment":              {},
		"AuthorizationSubjectDepartment":       {},
		"AuthorizationSubjectsResolveRequest":  {},
		"AuthorizationSubjectsResolveResponse": {},
		"AuthorizationSubjectsResolver":        {},
		"AuthorizationUser":                    {},
		"AuthorizedSession":                    {},
		"AuthorizedSessionResolveRequest":      {},
		"AuthorizedSessionResolveResponse":     {},
		"AuthorizedSessionResolver":            {},
		"CompanyIdentity":                      {},
		"CompanyIdentityResolveRequest":        {},
		"CompanyIdentityResolveResponse":       {},
		"CompanyIdentityResolver":              {},
		"CompanyIdentityStatus":                {},
		"CompanyResolveRequest":                {},
		"CompanyResolveResponse":               {},
		"CompanyResolver":                      {},
		"CompanySearchRequest":                 {},
		"CompanySearchResponse":                {},
		"CompanySummary":                       {},
		"DevIdentity":                          {},
		"ErrCompanyIdentityNotFound":           {},
		"ErrCompanyNotFound":                   {},
		"ErrInvalidLoginWay":                   {},
		"ErrInvalidPrincipal":                  {},
		"InjectorFunc":                         {},
		"InternalSessionResolverClient":        {},
		"JWTConfig":                            {},
		"LoadJWTConfig":                        {},
		"LoginStatus":                          {},
		"LoginWay":                             {},
		"IssueIdentityToken":                   {},
		"ParseLegacyToken":                     {},
		"ParseToken":                           {},
		"Role":                                 {},
		"SessionPrincipal":                     {},
		"SessionResolveRequest":                {},
		"SessionResolveResponse":               {},
		"SessionResolver":                      {},
		"SessionResolverClientOptions":         {},
		"State":                                {},
	}

	for _, path := range packageGoFiles(t, ".") {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for name := range declaredNames(file) {
			if _, exists := forbidden[name]; exists {
				t.Errorf("%s still declares retired identity symbol %s", path, name)
			}
		}
	}

	claims := userClaimsFields(t)
	wantFields := map[string]bool{"RegisteredClaims": true, "AuthorizedParty": true}
	if len(claims) != len(wantFields) {
		t.Fatalf("UserClaims fields = %v, want only %v", claims, wantFields)
	}
	for field := range wantFields {
		if !claims[field] {
			t.Errorf("UserClaims is missing %s", field)
		}
	}
	for _, field := range []string{"UserID", "UIN", "CompanyID", "MembershipEpoch", "IssuedAt", "ExpiresAt", "Audience", "LoginWay"} {
		if claims[field] {
			t.Errorf("UserClaims still declares legacy numeric field %s", field)
		}
	}
}

func packageGoFiles(t *testing.T, directory string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(directory, "*.go"))
	if err != nil {
		t.Fatalf("glob Go files: %v", err)
	}
	files := paths[:0]
	for _, path := range paths {
		if !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
	}
	return files
}

func declaredNames(file *ast.File) map[string]struct{} {
	names := make(map[string]struct{})
	ast.Inspect(file, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.FuncDecl:
			names[value.Name.Name] = struct{}{}
		case *ast.TypeSpec:
			names[value.Name.Name] = struct{}{}
		case *ast.ValueSpec:
			for _, name := range value.Names {
				names[name.Name] = struct{}{}
			}
		}
		return true
	})
	return names
}

func userClaimsFields(t *testing.T) map[string]bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "claims.go", nil, 0)
	if err != nil {
		t.Fatalf("parse claims.go: %v", err)
	}
	fields := make(map[string]bool)
	ast.Inspect(file, func(node ast.Node) bool {
		typeSpec, ok := node.(*ast.TypeSpec)
		if !ok || typeSpec.Name.Name != "UserClaims" {
			return true
		}
		structure, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			t.Fatal("UserClaims is not a struct")
		}
		for _, field := range structure.Fields.List {
			if len(field.Names) == 0 {
				embedded, ok := field.Type.(*ast.SelectorExpr)
				if !ok {
					t.Errorf("UserClaims embedded field type = %T, want selector", field.Type)
					continue
				}
				fields[embedded.Sel.Name] = true
				continue
			}
			for _, name := range field.Names {
				fields[name.Name] = true
			}
		}
		return false
	})
	return fields
}
