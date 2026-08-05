package errcode

import "net/http"

const (
	// CodeOK 成功。
	CodeOK uint32 = 0

	ErrCode_BadRequest    = http.StatusBadRequest
	ErrCode_InternalError = http.StatusInternalServerError
	ErrCode_NotFound      = http.StatusNotFound
	ErrCode_Unauthorized  = http.StatusUnauthorized
	ErrCode_NoPermission  = http.StatusForbidden
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