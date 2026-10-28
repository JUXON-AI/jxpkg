package runtime

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestLegacyNumericContextHelpersAreRetired(t *testing.T) {
	forbidden := map[string]struct{}{
		"AuthorizationContext":    {},
		"BrowserSessionExpiresAt": {},
		"CompanyID":               {},
		"LoginWay":                {},
		"MembershipEpoch":         {},
		"UIN":                     {},
		"UserID":                  {},
		"loginStatus":             {},
	}
	file, err := parser.ParseFile(token.NewFileSet(), "context.go", nil, 0)
	if err != nil {
		t.Fatalf("parse context.go: %v", err)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		function, ok := node.(*ast.FuncDecl)
		if !ok {
			return true
		}
		if _, retired := forbidden[function.Name.Name]; retired {
			t.Errorf("context.go still declares retired helper %s", function.Name.Name)
		}
		return true
	})

	constants, err := parser.ParseFile(token.NewFileSet(), "../constants/gin.go", nil, 0)
	if err != nil {
		t.Fatalf("parse constants/gin.go: %v", err)
	}
	forbiddenConstants := map[string]struct{}{
		"CtxKeyAuthorizationContext": {},
		"CtxKeyCompanyID":            {},
		"CtxKeyLoginStatus":          {},
		"CtxKeyMembershipEpoch":      {},
		"CtxKeyUIN":                  {},
		"CtxKeyUserID":               {},
	}
	ast.Inspect(constants, func(node ast.Node) bool {
		value, ok := node.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for _, name := range value.Names {
			if _, retired := forbiddenConstants[name.Name]; retired {
				t.Errorf("constants/gin.go still declares retired context key %s", name.Name)
			}
		}
		return true
	})
}
