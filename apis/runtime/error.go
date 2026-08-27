package runtime

import (
	"fmt"
	"net/http"

	"github.com/JUXON-AI/jxpkg/apis/apiobj"
	"github.com/JUXON-AI/jxpkg/apis/errcode"
	"github.com/JUXON-AI/jxpkg/config"

	"github.com/gin-gonic/gin"

	"github.com/JUXON-AI/jxpkg/apis/constants"
)

// ResponseMessage 以统一格式返回 API 响应（含 code、message、env、request_id）。
func ResponseMessage(ctx *gin.Context, code uint32, msgs ...interface{}) {
	msg := formatMessage(msgs...)
	ctx.Set(constants.CtxKeyCode, int(code))
	ctx.AbortWithStatusJSON(http.StatusOK, apiobj.BaseResponse{
		Code:      code,
		Message:   msg,
		Env:       config.Conf().MainConf.Env,
		RequestID: ctx.GetString(constants.CtxKeyRequestID),
	})
}

// Success 返回成功响应（code=0）。
func Success(ctx *gin.Context, msgs ...interface{}) {
	ResponseMessage(ctx, errcode.CodeOK, msgs...)
}

// BadRequest 返回 400 错误响应。
func BadRequest(ctx *gin.Context, msgs ...interface{}) {
	ResponseMessage(ctx, errcode.ErrCode_BadRequest, msgs...)
}

// InternalError 返回 500 错误响应。
func InternalError(ctx *gin.Context, msgs ...interface{}) {
	ResponseMessage(ctx, errcode.ErrCode_InternalError, msgs...)
}

// BadRequestWithCode 返回指定错误码的 400 响应。
func BadRequestWithCode(ctx *gin.Context, code uint32, msgs ...interface{}) {
	ResponseMessage(ctx, code, msgs...)
}

// InternalErrorWithCode 返回指定错误码的 500 响应。
func InternalErrorWithCode(ctx *gin.Context, code uint32, msgs ...interface{}) {
	ResponseMessage(ctx, code, msgs...)
}

func formatMessage(msgs ...interface{}) string {
	if len(msgs) == 0 {
		return ""
	}
	if len(msgs) == 1 {
		return fmt.Sprint(msgs[0])
	}
	if format, ok := msgs[0].(string); ok {
		return fmt.Sprintf(format, msgs[1:]...)
	}
	return fmt.Sprint(msgs...)
}
