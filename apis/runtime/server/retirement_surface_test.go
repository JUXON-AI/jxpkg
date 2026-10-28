package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLegacyAccountRouterSurfaceIsRetired(t *testing.T) {
	forbidden := map[string]struct{}{
		"AuthInject":                         {},
		"Inject":                             {},
		"NewBrowserSessionOption":            {},
		"PRequireAuthorizedBrowserSession":   {},
		"PRequireBearer":                     {},
		"PRequireBrowserSession":             {},
		"PRequireLogin":                      {},
		"authInjector":                       {},
		"browserAuthorizedSessionMiddleware": {},
		"browserBearerMiddleware":            {},
		"browserCSRFMiddleware":              {},
		"browserSessionErr":                  {},
		"browserSessionMiddleware":           {},
		"publishBrowserPrincipal":            {},
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
					t.Errorf("%s still declares retired router entry %s", path, value.Name.Name)
				}
			case *ast.TypeSpec:
				if _, retired := forbidden[value.Name.Name]; retired {
					t.Errorf("%s still declares retired router type %s", path, value.Name.Name)
				}
			case *ast.Field:
				for _, name := range value.Names {
					if _, retired := forbidden[name.Name]; retired {
						t.Errorf("%s still declares retired router field %s", path, name.Name)
					}
				}
			}
			return true
		})
	}
}

func TestRouterPostRunsExplicitBrowserHandlerWithoutLegacyAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := NewRouter("/v1/")
	called := false
	router.Post("profile.Get", func(ctx *gin.Context) {
		called = true
		ctx.Status(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/profile.Get", nil)
	router.GinEngine().ServeHTTP(recorder, request)

	if !called || recorder.Code != http.StatusNoContent {
		t.Fatalf("explicit handler called = %v, status = %d; want true, %d", called, recorder.Code, http.StatusNoContent)
	}
}
