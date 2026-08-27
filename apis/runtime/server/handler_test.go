package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

type bodyLimitRequest struct {
	Data string `json:"data"`
}

type bodyLimitResponse struct{}

func TestTransAPIRejectsOversizedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	body := `{"data":"` + strings.Repeat("a", int(maxRequestBodyBytes)) + `"}`
	ctx.Request = httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	called := false

	transAPI(func(_ *gin.Context, _ *bodyLimitRequest, _ *bodyLimitResponse) {
		called = true
	})(ctx)

	if called {
		t.Fatal("handler should not be called for an oversized request")
	}
	if !ctx.IsAborted() {
		t.Fatal("context should be aborted for an oversized request")
	}
	if !strings.Contains(recorder.Body.String(), "request body too large") {
		t.Fatalf("response = %q, want request body too large error", recorder.Body.String())
	}
}

func TestTransAPIUsesConfiguredBodyLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	body := `{"data":"` + strings.Repeat("a", int(maxRequestBodyBytes)) + `"}`

	t.Run("allows body above default limit", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
		called := false

		API(func(_ *gin.Context, _ *bodyLimitRequest, _ *bodyLimitResponse) {
			called = true
		}, WithMaxRequestBodyBytes(2<<20))(ctx)

		if !called {
			t.Fatalf("handler was not called, response = %q", recorder.Body.String())
		}
	})

	t.Run("rejects body above configured limit", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
		called := false

		API(func(_ *gin.Context, _ *bodyLimitRequest, _ *bodyLimitResponse) {
			called = true
		}, WithMaxRequestBodyBytes(maxRequestBodyBytes/2))(ctx)

		if called {
			t.Fatal("handler should not be called for an oversized request")
		}
		if !strings.Contains(recorder.Body.String(), "request body too large") {
			t.Fatalf("response = %q, want request body too large error", recorder.Body.String())
		}
	})
}
