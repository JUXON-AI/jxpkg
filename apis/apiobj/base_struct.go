package apiobj

// BaseRequest 通用 API 请求头。
type BaseRequest struct {
	Cmd     string `json:"cmd"`
	Env     string `json:"env,omitempty"`
	Version string `json:"version,omitempty"`
}

// BaseResponse 通用 API 响应结构。
type BaseResponse struct {
	Code        uint32                 `json:"code"`
	Message     string                 `json:"message,omitempty"`
	MessageData map[string]interface{} `json:"-"`
	Env         string                 `json:"env,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
}

// QueryRequest 带分页的查询请求。
type QueryRequest struct {
	BaseRequest
	Request PageQuery
}

// DetailIdRequest 按 ID 查询详情的请求。
type DetailIdRequest struct {
	BaseRequest
	Request struct {
		ID uint `json:"id"`
	}
}

// DetailNameRequest 按 ID 或名称查询详情的请求。
type DetailNameRequest struct {
	BaseRequest
	Request struct {
		ID   uint   `json:"id"`
		Name string `json:"name"`
	}
}
