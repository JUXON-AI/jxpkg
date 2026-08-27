package apiobj

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type queryFields struct{}

func (queryFields) AllowOrderFields() []string  { return []string{"id", "created_at"} }
func (queryFields) AllowFilterFields() []string { return []string{"name"} }

func TestPageQueryFillAndValidate(t *testing.T) {
	query := PageQuery{}
	query.Fill()
	if query.Limit != DefaultPageSize {
		t.Fatalf("Limit = %d, want %d", query.Limit, DefaultPageSize)
	}
	if err := query.Validate(queryFields{}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestPageQueryValidateFields(t *testing.T) {
	tests := []struct {
		name  string
		query PageQuery
	}{
		{name: "invalid offset", query: PageQuery{Offset: -1, Limit: 10}},
		{name: "invalid limit", query: PageQuery{Limit: PageMaxCount + 1}},
		{name: "invalid order", query: PageQuery{Limit: 10, OrderBy: []string{"password DESC"}}},
		{
			name: "invalid filter",
			query: PageQuery{
				Limit:   10,
				Filters: []Filter{{Field: "password", Value: []string{"x"}}},
			},
		},
		{
			name: "empty filter",
			query: PageQuery{
				Limit:   10,
				Filters: []Filter{{Field: "name"}},
			},
		},
		{name: "invalid time range", query: PageQuery{Limit: 10, BeginTime: time.Now(), EndTime: time.Now().Add(-time.Hour)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.query.Validate(queryFields{}); err == nil {
				t.Fatal("Validate error = nil")
			}
		})
	}
}

func TestPageQueryJSONFields(t *testing.T) {
	data, err := json.Marshal(PageQuery{
		Offset:  1,
		Limit:   10,
		ListAll: true,
		OrderBy: []string{"id DESC"},
		Filters: []Filter{{Field: "name", Value: []string{"demo"}, ExactMatch: true}},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	jsonText := string(data)
	for _, field := range []string{"offset", "limit", "list_all", "order_by", "filters", "field", "value", "exact_match"} {
		if !strings.Contains(jsonText, `"`+field+`"`) {
			t.Fatalf("JSON = %s, want field %q", jsonText, field)
		}
	}
}
