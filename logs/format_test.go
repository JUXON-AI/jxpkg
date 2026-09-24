package logs

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTrimTextKeepsShortValuesUnchanged(t *testing.T) {
	cases := []string{"", "abc", "凭证", strings.Repeat("x", textLimit)}
	for _, in := range cases {
		if got := TrimText(in); got != in {
			t.Fatalf("TrimText(%q) = %q, want it unchanged", in, got)
		}
	}
}

func TestTrimTextSummarizesLongValues(t *testing.T) {
	in := strings.Repeat("a", textLimit+1)
	got := TrimText(in)
	want := "len=501 head=\"" + strings.Repeat("a", textHead) + "\""
	if got != want {
		t.Fatalf("TrimText(long) = %q, want %q", got, want)
	}
}

// 前缀必须切成完整的 rune：s[:200] 在中文/emoji 上会切出半个字符，
// 日志里是乱码，而且 grep 那个前缀会时灵时不灵。
func TestTrimTextCutsOnRuneBoundary(t *testing.T) {
	// 每个「汉」占 3 字节，200 不是 3 的倍数，所以朴素切片一定会切开一个字符。
	in := strings.Repeat("汉", 200) // 600 字节
	got := TrimText(in)

	head, ok := parseHead(t, got)
	if !ok {
		t.Fatalf("TrimText 的输出没有 head= 段：%q", got)
	}
	if !utf8.ValidString(head) {
		t.Fatalf("head 不是合法 UTF-8（被切开了）：%q", head)
	}
	if utf8.RuneCountInString(head) != 66 { // 66×3 = 198 字节 ≤ 200，67×3 = 201 > 200
		t.Fatalf("head 的 rune 数 = %d, want 66", utf8.RuneCountInString(head))
	}
}

// 字符串本身含非法字节时，不要为了「修好它」把前缀吃光——只剥尾部那个不完整的 rune。
func TestTrimTextToleratesInvalidBytes(t *testing.T) {
	in := strings.Repeat("a", textHead-1) + "\xff" + strings.Repeat("b", textLimit)
	got := TrimText(in)
	head, ok := parseHead(t, got)
	if !ok {
		t.Fatalf("TrimText 的输出没有 head= 段：%q", got)
	}
	// 尾部的 0xff 被剥掉，前面 199 个 'a' 必须还在。
	if !strings.HasPrefix(head, strings.Repeat("a", textHead-1)) {
		t.Fatalf("前缀被吃掉了：%q", head)
	}
}

func TestTrimListKeepsShortSlicesAsSlices(t *testing.T) {
	in := []int{1, 2, 3}
	got := TrimList(in)
	typed, ok := got.([]int)
	if !ok {
		t.Fatalf("TrimList(短) 返回 %T, want []int（要能交给 %%v 渲染成 [1 2 3]）", got)
	}
	if len(typed) != len(in) {
		t.Fatalf("TrimList(短) 丢了元素：%v", typed)
	}
	// 边界：恰好等于门槛时也必须原样。
	exact := make([]int, listLimit)
	if _, ok := TrimList(exact).([]int); !ok {
		t.Fatalf("TrimList(%d 项) 应当原样返回切片", listLimit)
	}
}

func TestTrimListSummarizesLongSlices(t *testing.T) {
	in := make([]int, listLimit+1)
	for i := range in {
		in[i] = i
	}
	got := TrimList(in)
	text, ok := got.(string)
	if !ok {
		t.Fatalf("TrimList(长) 返回 %T, want string", got)
	}
	want := "len=11 head=[0 1 2 3 4]"
	if text != want {
		t.Fatalf("TrimList(long) = %q, want %q", text, want)
	}
}

// map 的键序在 Go 里是随机的：裸 %v 打两次结果不同。TrimMap 的整点就在这条。
func TestTrimMapIsDeterministic(t *testing.T) {
	in := map[string]int{"b": 2, "a": 1, "d": 4, "c": 3}
	first := TrimMap(in)
	for i := 0; i < 50; i++ {
		if got := TrimMap(in); got != first {
			t.Fatalf("TrimMap 不稳定：%q vs %q", first, got)
		}
	}
	if first != "map[a:1 b:2 c:3 d:4]" {
		t.Fatalf("TrimMap = %q, want 按键排序", first)
	}
}

func TestTrimMapSummarizesLongMaps(t *testing.T) {
	in := map[string]int{}
	for _, k := range []string{"e", "d", "c", "b", "a", "k", "j", "i", "h", "g", "f"} {
		in[k] = len(in)
	}
	got := TrimMap(in)
	if !strings.HasPrefix(got, "len=11 head=map[") {
		t.Fatalf("TrimMap(长) = %q, want len=11 head=map[...", got)
	}
	// 前 5 个键必须按排序取，而不是按遍历顺序。
	if !strings.Contains(got, "a:4 b:3 c:2 d:1 e:0") {
		t.Fatalf("TrimMap(长) 取的 5 项不是排序后的前 5：%q", got)
	}
}

// parseHead 从 `len=N head="..."` 里取回未转义的 head 内容。
func parseHead(t *testing.T, summary string) (string, bool) {
	t.Helper()
	idx := strings.Index(summary, `head="`)
	if idx < 0 {
		return "", false
	}
	quoted := summary[idx+len("head="):]
	out, err := strconv.Unquote(quoted)
	if err != nil {
		t.Fatalf("head 段不是合法的 Go 引号串：%q", quoted)
	}
	return out, true
}
