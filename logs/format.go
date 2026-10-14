package logs

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// JSON 将 v 序列化为 JSON，序列化失败时返回空字符串。
func JSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// 过长值的裁剪门槛。
//
// **它们是全仓唯一的口径**，调用点不得自己判长度（JX 的 CONV-02「一个决策点只在一个地方」）。
// 取宽松一组：目标是「值基本都在日志里」，截断只是防爆手段，不是常态。
const (
	textLimit = 500 // 字节；≤ 此值原样返回
	textHead  = 200 // 字节；超过时保留的前缀长度
	listLimit = 10  // 项数；≤ 此值原样返回
	listHead  = 5   // 项数；超过时保留的前缀长度
)

// TrimText 把过长的字符串裁成可读的日志片段，供 `%v` 使用。
//
// 长度 ≤ textLimit 字节时**原样返回**，不加引号（短值直接可读）。
// 超过时返回 `len=<字节数> head="<≤ textHead 字节的完整 UTF-8 前缀>"`。
//
// 前缀按 **rune 边界**收尾：直接 `s[:200]` 可能切出半个多字节字符，
// 日志里是乱码，而且 grep 那个前缀会时灵时不灵。
//
// 它**不做掩码、不做脱敏**。JX 的日志规范要求凭据以原值进日志，
// 边界在 HTTP 响应体那一边，不在这里（见 jx-developer 的 logging.md §3）。
func TrimText(s string) string {
	if len(s) <= textLimit {
		return s
	}
	head := s[:textHead]
	// 只剥掉尾部那个不完整的 rune；字符串本身若含非法字节，不动它。
	for len(head) > 0 {
		r, size := utf8.DecodeLastRuneInString(head)
		if r != utf8.RuneError || size > 1 {
			break
		}
		head = head[:len(head)-1]
	}
	return fmt.Sprintf("len=%d head=%q", len(s), head)
}

// TrimList 把过长的切片裁成可读的日志片段，供 `%v` 使用。
//
// 长度 ≤ listLimit 项时**返回切片本身**，由 `%v` 渲染成 `[a b c]`；
// 超过时返回 `len=<项数> head=[前 listHead 项]`。
//
// 返回 `any` 是因为两条分支的类型不同。这个返回值唯一的用途就是交给 `%v`，
// 不要在别处依赖它的动态类型。
func TrimList[T any](v []T) any {
	if len(v) <= listLimit {
		return v
	}
	return fmt.Sprintf("len=%d head=%v", len(v), v[:listHead])
}

// TrimMap 把过长的 map 裁成可读的日志片段，供 `%v` 使用。
//
// 与 TrimList 不同，它**总是**返回渲染好的字符串（不返回 map 本身），
// 因为 Go 里 `%v` 打 map 的**键序是随机的**——两次运行的同一份日志不相等，无法 diff。
// 这里按 key 排序后渲染，于是输出是确定的。
//
// 键类型受限于 cmp.Ordered（string / 整数 / 浮点）：排序需要它。
// 键是其它可比较类型时，用 `JSON` 或 `TrimText(fmt.Sprint(m))`。
//
// **已知边界：浮点键里的 NaN 排不稳定。** NaN 不与任何值相等（包括它自己），
// 所以「多个 NaN 键之间」的先后没有确定答案，而 slices.SortFunc 不是稳定排序。
// 日志里用 float 键的 map 请改走 `JSON`。非 NaN 的浮点键没有这个问题。
//
// 值一律从 range 里成对取，而不是「先排序键、再 m[key] 取回」——
// 后者对 NaN 键会取到零值（NaN != NaN，查不到）。
func TrimMap[K cmp.Ordered, V any](m map[K]V) string {
	type entry struct {
		key   K
		value V
	}
	entries := make([]entry, 0, len(m))
	for key, value := range m {
		entries = append(entries, entry{key: key, value: value})
	}
	slices.SortFunc(entries, func(a, b entry) int { return cmp.Compare(a.key, b.key) })
	if len(entries) > listLimit {
		entries = entries[:listHead]
	}

	var b strings.Builder
	if len(m) > listLimit {
		fmt.Fprintf(&b, "len=%d head=map[", len(m))
	} else {
		b.WriteString("map[")
	}
	for i, e := range entries {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%v:%v", e.key, e.value)
	}
	b.WriteByte(']')
	return b.String()
}
