// Package safeerror 保留内部错误分类，同时由调用方提供固定的对外错误文本。
package safeerror

type wrapped struct {
	message string
	cause   error
}

// Wrap 用固定、安全文本包装原因；message 不得来自凭证、配置或上游响应。
// errors.Is/As 仍可访问内部原因，日志和响应只应输出外层错误。原因为空时返回 nil。
func Wrap(message string, cause error) error {
	if cause == nil {
		return nil
	}
	return &wrapped{message: message, cause: cause}
}

func (e *wrapped) Error() string { return e.message }
func (e *wrapped) Unwrap() error { return e.cause }
