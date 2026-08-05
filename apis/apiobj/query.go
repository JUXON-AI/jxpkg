package apiobj

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	// DefaultPageSize 默认每页条数。
	DefaultPageSize = 10
	// PageMaxCount 单页最大条数。
	PageMaxCount = 150
)

var earliestTime = time.Date(2015, time.December, 0, 0, 0, 0, 0, time.Local).Unix()

type allowOrderFielder interface {
	AllowOrderFields() []string
}

type allowFilterFielder interface {
	AllowFilterFields() []string
}

// PageQuery 分页查询参数。
type PageQuery struct {
	Offset    int       `json:",omitempty"`
	Limit     int       `json:",omitempty"`
	ListAll   bool      `json:",omitempty"`
	OrderBy   []string  `json:",omitempty"`
	Filters   []Filter  `json:",omitempty"`
	BeginTime time.Time `json:",omitempty"`
	EndTime   time.Time `json:",omitempty"`

	IsBackend  bool `json:"-"`
	CompanyID  uint `json:"-"`
	EmployeeID uint `json:"-"`
	Uin        uint `json:"-"`
}

// Filter 查询过滤器，支持精确匹配和模糊匹配。
type Filter struct {
	Field      string
	Value      []string
	ExactMatch bool
}

// Fill 设置分页默认值（来自 HTTP 请求参数）。
func (p *PageQuery) Fill(req *http.Request) {
	if p.Offset <= 0 {
		p.Offset = 0
	}
	if p.Limit <= 0 || p.Limit > PageMaxCount {
		p.Limit = DefaultPageSize
	}
	if p.ListAll {
		p.Limit = PageMaxCount
	}
}

// IsValite 校验分页参数，并检查排序和过滤字段是否在白名单中。
func (p PageQuery) IsValite(allower interface{}) error {
	if p.Offset < 0 {
		return fmt.Errorf("offset is invalid, %v", p.Offset)
	}
	if p.Limit <= 0 || p.Limit > PageMaxCount {
		return fmt.Errorf("limit is invalid, %v", p.Limit)
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
			if !containsString(allowFilterFields, f.Field) {
				return fmt.Errorf("unsupported filter field: %s", f.Field)
			}
		}
	}
	return nil
}

// QueryResponse 分页查询响应。
type QueryResponse struct {
	Total  int64 `json:"total"`
	Offset int   `json:"offset"`
	Limit  int   `json:"limit"`
}

func containsString(arr []string, str string) bool {
	for _, v := range arr {
		if v == str {
			return true
		}
	}
	return false
}