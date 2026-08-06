package runtime

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JUXON-AI/jxpkg/apis/errcode"
	"github.com/gin-gonic/gin"
)

func TestErrorResponsesUseHTTPStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		respond    func(*gin.Context)
		wantStatus int
	}{
		{name: "bad request", respond: func(ctx *gin.Context) { BadRequest(ctx, "invalid request") }, wantStatus: http.StatusBadRequest},
		{name: "internal error", respond: func(ctx *gin.Context) { InternalError(ctx, "internal server error") }, wantStatus: http.StatusInternalServerError},
		{name: "business bad request", respond: func(ctx *gin.Context) { BadRequestWithCode(ctx, 10001, "invalid") }, wantStatus: http.StatusBadRequest},
		{name: "unauthorized", respond: func(ctx *gin.Context) { ResponseMessage(ctx, errcode.ErrCode_Unauthorized, "unauthorized") }, wantStatus: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			tt.respond(ctx)
			if recorder.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, recorder.Code)
			}
		})
	}
}
