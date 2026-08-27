package logs

import "encoding/json"

// JSON 将 v 序列化为 JSON，序列化失败时返回空字符串。
func JSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
