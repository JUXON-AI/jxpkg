// Package requestid 在标准 Context 和 HTTP 边界间传递已有请求标识。
package requestid

import "context"

type contextKey struct{}

// Valid 限制日志及 HTTP 中的标识为最多128个安全 ASCII 字符。
func Valid(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// FromContext 读取已有标识，兼容 HTTP Runtime 的 reqid 键，不生成新标识。
func FromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(contextKey{}).(string); ok && Valid(id) {
		return id
	}
	if id, ok := ctx.Value("reqid").(string); ok && Valid(id) {
		return id
	}
	return ""
}

// WithContext 将有效标识传给下游；无效标识不写入上下文。
func WithContext(ctx context.Context, id string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if !Valid(id) {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, id)
}
