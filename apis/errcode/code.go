package errcode

import "net/http"

const (
	// CodeOK 成功。
	CodeOK uint32 = 0

	// ErrCode_BadRequest 表示请求参数不合法。
	ErrCode_BadRequest = http.StatusBadRequest

	// ErrCode_InternalError 表示服务内部错误。
	ErrCode_InternalError = http.StatusInternalServerError

	// ErrCode_NotFound 表示目标资源不存在。
	ErrCode_NotFound = http.StatusNotFound

	// ErrCode_Unauthorized 表示用户凭据无效。
	ErrCode_Unauthorized = http.StatusUnauthorized

	// ErrCode_NoPermission 表示当前身份无权执行操作。
	ErrCode_NoPermission = http.StatusForbidden

	// ErrCode_Conflict 表示请求与当前资源状态冲突。
	ErrCode_Conflict = http.StatusConflict

	// ErrCode_TooManyRequests 表示请求超过服务限流。
	ErrCode_TooManyRequests = http.StatusTooManyRequests

	// ErrCode_ServiceUnavailable 表示依赖服务暂时不可用。
	ErrCode_ServiceUnavailable = http.StatusServiceUnavailable
)

var errCodeMap = map[uint32]string{}

// Register 注册业务错误码及其对应的消息。
func Register(code uint32, message string) {
	errCodeMap[code] = message
}

// GetMessage 查询错误码对应的消息。
func GetMessage(code uint32) string {
	if msg, ok := errCodeMap[code]; ok {
		return msg
	}
	return ""
}
