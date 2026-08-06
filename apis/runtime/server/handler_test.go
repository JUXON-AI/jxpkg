package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

type decodeRequestInput struct {
	Name string `json:"name"`
}

func TestDecodeRequestAllowsEmptyBody(t *testing.T) {
	ctx := newDecodeContext(http.MethodGet, "")
	var input decodeRequestInput
	if err := decodeRequest(ctx, &input); err != nil {
		t.Fatalf("empty request body rejected: %v", err)
	}
}

func TestDecodeRequestRejectsUnknownField(t *testing.T) {
	ctx := newDecodeContext(http.MethodPost, `{"unknown":true}`)
	var input decodeRequestInput
	if err := decodeRequest(ctx, &input); err == nil {
		t.Fatal("expected unknown JSON field to be rejected")
	}
}

func TestDecodeRequestRejectsMultipleValues(t *testing.T) {
	ctx := newDecodeContext(http.MethodPost, `{"name":"one"}{"name":"two"}`)
	var input decodeRequestInput
	if err := decodeRequest(ctx, &input); err == nil {
		t.Fatal("expected multiple JSON values to be rejected")
	}
}

func newDecodeContext(method, body string) *gin.Context {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(method, "/", strings.NewReader(body))
	return ctx
}
