package middleware

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyAccountAuthenticationMiddlewareIsRetired(t *testing.T) {
	forbidden := map[string]struct{}{
		"BearerLoginStatusMiddleware":        {},
		"BrowserSessionBinding":              {},
		"BrowserSessionHandlers":             {},
		"BrowserSessionOptions":              {},
		"DefaultCSRFHeader":                  {},
		"NewBearerLoginStatusMiddleware":     {},
		"NewBrowserSessionHandlers":          {},
		"PermissionFailureHandler":           {},
		"RequireAuthenticated":               {},
		"RequirePermission":                  {},
		"ResolveAuthorizationContext":        {},
		"abortAuth":                          {},
		"bearerLoginStatusMiddleware":        {},
		"bearerToken":                        {},
		"browserAuthorizedSessionMiddleware": {},
		"browserBearerMiddleware":            {},
		"browserSessionMiddleware":           {},
		"csrfMiddleware":                     {},
		"failLoginStatus":                    {},
		"failedLoginStatusMiddleware":        {},
		"matchingCookies":                    {},
		"normalizeBrowserSessionOptions":     {},
		"resolverError":                      {},
		"validateSessionPrincipal":           {},
	}

	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob Go files: %v", err)
	}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.FuncDecl:
				if _, retired := forbidden[value.Name.Name]; retired {
					t.Errorf("%s still declares retired middleware %s", path, value.Name.Name)
				}
			case *ast.TypeSpec:
				if _, retired := forbidden[value.Name.Name]; retired {
					t.Errorf("%s still declares retired middleware type %s", path, value.Name.Name)
				}
			case *ast.ValueSpec:
				for _, name := range value.Names {
					if _, retired := forbidden[name.Name]; retired {
						t.Errorf("%s still declares retired middleware value %s", path, name.Name)
					}
				}
			}
			return true
		})
	}
}
