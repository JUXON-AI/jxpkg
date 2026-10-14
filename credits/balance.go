package credits

import (
	"bytes"
	"context"
	"encoding/json"
)

// BalancePath 是员工 wallet 快照的独立工作负载入口。
const BalancePath = "/internal/credits/balance"

// Balance 仅包含 New API 原始 wallet 单位，不包含调用凭据。
type Balance struct {
	// State 为 ready 或 pending；pending 不表示零余额。
	State string `json:"state"`
	// Quota 是剩余额度，可能因最终结算为负数。
	Quota int64 `json:"quota"`
	// UsedQuota 是累计已用额度，不是本周消耗。
	UsedQuota int64 `json:"used_quota"`
}

// ValidateBalance 验证状态及浏览器可精确表示的原始整数。
func ValidateBalance(b Balance) error {
	const maxExactInteger = int64(1<<53 - 1)
	if (b.State != "ready" && b.State != "pending") || b.Quota < -maxExactInteger || b.Quota > maxExactInteger || b.UsedQuota < 0 || b.UsedQuota > maxExactInteger {
		return ErrUnavailable
	}
	return nil
}

// GetBalance 查询指定员工余额，不领取 default，不缓存或重试。
func (c *Client) GetBalance(ctx context.Context, subject Subject) (Balance, error) {
	var wire balanceWire
	if err := c.call(ctx, subject, BalancePath, &wire); err != nil {
		return Balance{}, err
	}
	if wire.State == nil || wire.Quota == nil || wire.UsedQuota == nil {
		return Balance{}, ErrUnavailable
	}
	b := Balance{State: *wire.State, Quota: *wire.Quota, UsedQuota: *wire.UsedQuota}
	if err := ValidateBalance(b); err != nil {
		return Balance{}, err
	}
	return b, nil
}

type balanceWire struct {
	State     *string
	Quota     *int64
	UsedQuota *int64
}

// UnmarshalJSON 拒绝重复、大小写歧义和未知余额字段，不将缺失字段解释为零。
func (b *balanceWire) UnmarshalJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return ErrUnavailable
	}
	seen := make(map[string]bool, 3)
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return ErrUnavailable
		}
		seen[name] = true
		switch name {
		case "state":
			err = d.Decode(&b.State)
		case "quota":
			err = d.Decode(&b.Quota)
		case "used_quota":
			err = d.Decode(&b.UsedQuota)
		default:
			return ErrUnavailable
		}
		if err != nil {
			return ErrUnavailable
		}
	}
	closing, err := d.Token()
	if err != nil || closing != json.Delim('}') {
		return ErrUnavailable
	}
	return nil
}
