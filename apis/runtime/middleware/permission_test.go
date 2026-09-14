package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JUXON-AI/jxpkg/apis/constants"
	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/gin-gonic/gin"
)

type authorizationResolverFunc func(context.Context, auth.AuthorizationContextResolveRequest) (*auth.AuthorizationContextResolveResponse, error)

func (resolve authorizationResolverFunc) ResolveAuthorizationContext(ctx context.Context, input auth.AuthorizationContextResolveRequest) (*auth.AuthorizationContextResolveResponse, error) {
	return resolve(ctx, input)
}

func TestRequirePermission(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, test := range []struct {
		name     string
		allowed  bool
		err      error
		mismatch bool
		status   int
	}{
		{name: "allowed", allowed: true, status: http.StatusNoContent},
		{name: "denied", status: http.StatusForbidden},
		{name: "unavailable", err: errors.New("database unavailable"), status: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine := gin.New()
			resolver := authorizationResolverFunc(func(_ context.Context, input auth.AuthorizationContextResolveRequest) (*auth.AuthorizationContextResolveResponse, error) {
				if test.err != nil {
					return nil, test.err
				}
				result := &auth.AuthorizationContextResolveResponse{CompanyID: input.CompanyID, UIN: input.UIN, MembershipEpoch: input.MembershipEpoch}
				if test.mismatch {
					result.CompanyID++
				}
				if test.allowed {
					result.AllowedPermissions = []auth.PermissionCode{"agent.create"}
				}
				return result, nil
			})
			failure := func(ctx *gin.Context, err error) {
				status := http.StatusForbidden
				if AuthorizationUnavailable(err) {
					status = http.StatusServiceUnavailable
				}
				ctx.AbortWithStatus(status)
			}
			engine.POST("/resource", func(ctx *gin.Context) {
				ctx.Set(constants.CtxKeyCompanyID, uint(3))
				ctx.Set(constants.CtxKeyUIN, uint(2))
				ctx.Set(constants.CtxKeyMembershipEpoch, uint64(4))
			}, ResolveAuthorizationContext(resolver, "jxagent", []auth.PermissionCode{"agent.create"}, failure), RequirePermission("agent.create", failure), func(ctx *gin.Context) {
				ctx.Status(http.StatusNoContent)
			})
			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/resource", nil))
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d", recorder.Code, test.status)
			}
		})
	}
}

func TestResolveAuthorizationContextRejectsMismatchedResult(t *testing.T) {
	gin.SetMode(gin.TestMode)
	called := false
	engine := gin.New()
	engine.POST("/resource", func(ctx *gin.Context) {
		ctx.Set(constants.CtxKeyCompanyID, uint(3))
		ctx.Set(constants.CtxKeyUIN, uint(2))
		ctx.Set(constants.CtxKeyMembershipEpoch, uint64(4))
	}, ResolveAuthorizationContext(authorizationResolverFunc(func(_ context.Context, input auth.AuthorizationContextResolveRequest) (*auth.AuthorizationContextResolveResponse, error) {
		return &auth.AuthorizationContextResolveResponse{CompanyID: input.CompanyID + 1, UIN: input.UIN, MembershipEpoch: input.MembershipEpoch}, nil
	}), "jxagent", nil, func(ctx *gin.Context, _ error) {
		ctx.Status(http.StatusServiceUnavailable)
	}), func(ctx *gin.Context) {
		called = true
		ctx.Status(http.StatusNoContent)
	})
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/resource", nil))
	if recorder.Code != http.StatusServiceUnavailable || called {
		t.Fatalf("status = %d, downstream called = %v", recorder.Code, called)
	}
}
