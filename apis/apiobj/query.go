package apiobj

import (
	"fmt"
	"strings"
	"time"
)

const (
	// DefaultPageSize 默认每页条数。
	DefaultPageSize = 10
	// PageMaxCount 单页最大条数。
	PageMaxCount = 150
)

type allowOrderFielder interface {
	AllowOrderFields() []string
}

type allowFilterFielder interface {
	AllowFilterFields() []string
}

// PageQuery 分页查询参数。
type PageQuery struct {
	// Offset 是非负的分页偏移量。
	Offset int `json:"offset,omitempty"`
	// Limit 是分页大小，0 使用 DefaultPageSize，最大为 PageMaxCount。
	Limit int `json:"limit,omitempty"`
	// ListAll 表示忽略 Offset 和 Limit 返回全部结果。
	ListAll bool `json:"list_all,omitempty"`
	// OrderBy 是排序表达式列表，例如 "created_at DESC"。
	OrderBy []string `json:"order_by,omitempty"`
	// Filters 是字段过滤条件列表。
	Filters []Filter `json:"filters,omitempty"`
	// BeginTime 是创建时间范围的起点。
	BeginTime time.Time `json:"begin_time,omitempty"`
	// EndTime 是创建时间范围的终点。
	EndTime time.Time `json:"end_time,omitempty"`

	// IsBackend 标记请求是否来自后台调用。
	IsBackend bool `json:"-"`
	// UserID 是服务端注入的当前用户 ID。
	UserID uint `json:"-"`
}

// Filter 查询过滤器，支持精确匹配和模糊匹配。
type Filter struct {
	// Field 是过滤字段名。
	Field string `json:"field"`
	// Value 是字段过滤值列表。
	Value []string `json:"value"`
	// ExactMatch 表示使用精确匹配，否则使用模糊匹配。
	ExactMatch bool `json:"exact_match"`
}

// Fill 设置分页默认值。
func (p *PageQuery) Fill() {
	if p.Limit == 0 {
		p.Limit = DefaultPageSize
	}
}

// Validate 校验分页参数，并检查排序和过滤字段是否在白名单中。
func (p PageQuery) Validate(allower interface{}) error {
	if p.Offset < 0 {
		return fmt.Errorf("offset is invalid, %v", p.Offset)
	}
	if p.Limit <= 0 || p.Limit > PageMaxCount {
		return fmt.Errorf("limit is invalid, %v", p.Limit)
	}
	if !p.BeginTime.IsZero() && !p.EndTime.IsZero() && p.EndTime.Before(p.BeginTime) {
		return fmt.Errorf("end_time must not be before begin_time")
	}
	var allowOrderFields, allowFilterFields []string
	if allower != nil {
		if orderAllower, ok := allower.(allowOrderFielder); ok {
			allowOrderFields = orderAllower.AllowOrderFields()
		}
		if filterAllower, ok := allower.(allowFilterFielder); ok {
			allowFilterFields = filterAllower.AllowFilterFields()
		}
	}
	if allowOrderFields != nil {
		for _, ob := range p.OrderBy {
			ob = strings.TrimSpace(ob)
			ob = strings.ToLower(ob)
			ob = strings.TrimSuffix(ob, " desc")
			ob = strings.TrimSuffix(ob, " asc")
			if !containsString(allowOrderFields, ob) {
				return fmt.Errorf("unsupported order field: %s", ob)
			}
		}
	}
	if allowFilterFields != nil {
		for _, f := range p.Filters {
			field := strings.ToLower(strings.TrimSpace(f.Field))
			if !containsString(allowFilterFields, field) {
				return fmt.Errorf("unsupported filter field: %s", field)
			}
			if len(f.Value) == 0 {
				return fmt.Errorf("filter value is empty: %s", field)
			}
		}
	}
	return nil
}

// QueryResponse 分页查询响应。
type QueryResponse struct {
	// Total 是符合条件的记录总数。
	Total int64 `json:"total"`
	// Offset 是本次查询使用的分页偏移量。
	Offset int `json:"offset"`
	// Limit 是本次查询使用的分页大小。
	Limit int `json:"limit"`
}

func containsString(arr []string, str string) bool {
	for _, v := range arr {
		if v == str {
			return true
		}
	}
	return false
}
