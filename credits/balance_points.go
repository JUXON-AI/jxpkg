package credits

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

var pointsDecimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})\.[0-9]{2}$`)

// BalancePoints 是 Credits 按当前配置计算的展示值；客户端不自行换算原始额度。
type BalancePoints struct {
	// Balance 是剩余积分，可为负；不足最小精度时保留方向。
	Balance string `json:"balance"`
	// Used 是累计已用积分，不可为负。
	Used string `json:"used"`
	// QuotaPerPoint 是计算本次展示值使用的原始额度比例。
	QuotaPerPoint int64 `json:"quota_per_point"`
	// Unit 是固定显示单位「分」。
	Unit string `json:"unit"`
}

func (p BalancePoints) valid() bool {
	balanceValid := p.Balance == "<0.01" || p.Balance == ">-0.01" || pointsDecimal.MatchString(strings.TrimPrefix(p.Balance, "-"))
	usedValid := p.Used == "<0.01" || pointsDecimal.MatchString(p.Used)
	return balanceValid && usedValid && p.QuotaPerPoint >= 1 && p.QuotaPerPoint <= 1_000_000_000 && p.Unit == "分"
}

// UnmarshalJSON 拒绝缺项、重复字段及大小写别名，保留积分小数文本。
func (p *BalancePoints) UnmarshalJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return ErrUnavailable
	}
	var value BalancePoints
	seen := make(map[string]bool, 4)
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return ErrUnavailable
		}
		seen[name] = true
		switch name {
		case "balance":
			err = d.Decode(&value.Balance)
		case "used":
			err = d.Decode(&value.Used)
		case "quota_per_point":
			err = d.Decode(&value.QuotaPerPoint)
		case "unit":
			err = d.Decode(&value.Unit)
		default:
			return ErrUnavailable
		}
		if err != nil {
			return ErrUnavailable
		}
	}
	closing, err := d.Token()
	if err != nil || closing != json.Delim('}') || !value.valid() {
		return ErrUnavailable
	}
	*p = value
	return nil
}
