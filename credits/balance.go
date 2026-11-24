package credits

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"regexp"
)

// BalancePath 是员工额度接口的稳定工作负载入口；响应类型由 UsageSummary 承载。
const BalancePath = "/internal/credits/balance"

var usageSummaryPoints = regexp.MustCompile(`^(?:-?(?:0|[1-9][0-9]{0,18})(?:\.[0-9]{1,12})?|<0\.01|>-0\.01)$`)

const maxUsageSummaryUnixSeconds = int64(1000000000000)

// UsageSummary 是不包含凭证和原始 quota 的员工额度摘要。
type UsageSummary struct {
	// State 为 ready、pending 或 uninitialized；pending 不表示零额度。
	State string `json:"state"`
	// MonthlyRemainingPercent 是本月剩余百分比；未知时为 nil。
	MonthlyRemainingPercent *float64 `json:"monthly_remaining_percent"`
	// NextResetAt 是下次重置 UTC Unix 秒；未知时为 nil。
	NextResetAt *int64 `json:"next_reset_at"`
	// SubscriptionEndsAt 是订阅结束 UTC Unix 秒；未知时为 nil。
	SubscriptionEndsAt *int64 `json:"subscription_ends_at"`
	// PointsBalance 是服务端生成的钱包积分展示字符串，不能用于前端换算；未知时为 nil。
	PointsBalance *string `json:"points_balance"`
}

// ValidateUsageSummary 验证三态及所有可空展示字段。
func ValidateUsageSummary(summary UsageSummary) error {
	if summary.State != "ready" && summary.State != "pending" && summary.State != "uninitialized" {
		return ErrUnavailable
	}
	if summary.MonthlyRemainingPercent != nil && (math.IsNaN(*summary.MonthlyRemainingPercent) || math.IsInf(*summary.MonthlyRemainingPercent, 0) || *summary.MonthlyRemainingPercent < 0 || *summary.MonthlyRemainingPercent > 100) {
		return ErrUnavailable
	}
	if (summary.NextResetAt != nil && (*summary.NextResetAt <= 0 || *summary.NextResetAt > maxUsageSummaryUnixSeconds)) || (summary.SubscriptionEndsAt != nil && (*summary.SubscriptionEndsAt <= 0 || *summary.SubscriptionEndsAt > maxUsageSummaryUnixSeconds)) {
		return ErrUnavailable
	}
	if summary.PointsBalance != nil && (len(*summary.PointsBalance) > 32 || !usageSummaryPoints.MatchString(*summary.PointsBalance)) {
		return ErrUnavailable
	}
	return nil
}

// GetUsageSummary 查询指定员工额度摘要，不领取 default、不缓存或重试。
func (c *Client) GetUsageSummary(ctx context.Context, subject Subject) (UsageSummary, error) {
	var wire usageSummaryWire
	if err := c.call(ctx, subject, BalancePath, &wire); err != nil {
		return UsageSummary{}, err
	}
	summary := UsageSummary{
		State:                   *wire.State,
		MonthlyRemainingPercent: wire.MonthlyRemainingPercent,
		NextResetAt:             wire.NextResetAt,
		SubscriptionEndsAt:      wire.SubscriptionEndsAt,
		PointsBalance:           wire.PointsBalance,
	}
	if err := ValidateUsageSummary(summary); err != nil {
		return UsageSummary{}, err
	}
	return summary, nil
}

type usageSummaryWire struct {
	State                   *string
	MonthlyRemainingPercent *float64
	NextResetAt             *int64
	SubscriptionEndsAt      *int64
	PointsBalance           *string
}

// UnmarshalJSON 要求完整字段集，并拒绝重复、大小写歧义和未知字段。
func (w *usageSummaryWire) UnmarshalJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return ErrUnavailable
	}
	seen := make(map[string]bool, 5)
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return ErrUnavailable
		}
		seen[name] = true
		switch name {
		case "state":
			err = d.Decode(&w.State)
		case "monthly_remaining_percent":
			err = d.Decode(&w.MonthlyRemainingPercent)
		case "next_reset_at":
			err = d.Decode(&w.NextResetAt)
		case "subscription_ends_at":
			err = d.Decode(&w.SubscriptionEndsAt)
		case "points_balance":
			err = d.Decode(&w.PointsBalance)
		default:
			return ErrUnavailable
		}
		if err != nil {
			return ErrUnavailable
		}
	}
	closing, err := d.Token()
	if err != nil || closing != json.Delim('}') || w.State == nil || len(seen) != 5 {
		return ErrUnavailable
	}
	return nil
}
