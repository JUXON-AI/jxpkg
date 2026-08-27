package task

import (
	"github.com/JUXON-AI/jxpkg/apis/apiobj"
	"github.com/JUXON-AI/jxpkg/apis/errcode"
)

// GetPendingTestRequest 获取一个待执行的任务请求体
type GetPendingTestRequest struct {
	apiobj.BaseRequest
	Request struct {
		TaskType string `json:"task_type"`
		WorkerID string `json:"worker_id"`
	}
}

func (req *GetPendingTestRequest) Validity(resp *GetPendingTestResponse) {
	if req.Request.TaskType == "" || req.Request.WorkerID == "" {
		resp.Code = errcode.ErrCode_BadRequest
		resp.Message = "参数错误"
	}

}

// GetPendingTestResponse 获取一个待执行的任务响应体
type GetPendingTestResponse struct {
	apiobj.BaseResponse
	Response struct {
		TaskID  uint   `json:"task_id"`
		Payload string `json:"payload"` // 任务内容
	}
}

// TaskCallBackRequest 任务回调请求体
type TaskCallBackRequest struct {
	apiobj.BaseRequest
	Request struct {
		TaskID       uint       `json:"task_id"`
		WorkerID     string     `json:"worker_id"`
		Status       TaskStatus `json:"status"`
		ErrorMessage string     `json:"error_message"`
		Result       string     `json:"result"`
	}
}

func (req *TaskCallBackRequest) Validity(resp *TaskCallBackResponse) {
	if req.Request.TaskID == 0 || req.Request.WorkerID == "" || req.Request.Status == "" {
		resp.Code = errcode.ErrCode_BadRequest
		resp.Message = "参数错误"
	}
}

// TaskCallBackResponse 任务回调响应体
type TaskCallBackResponse struct {
	apiobj.BaseResponse
}

// CheckInstanceRequest 健康检查实例
type CheckInstanceRequest struct {
	apiobj.BaseRequest
	Request struct {
		TaskType string `json:"task_type"`
		WorkerID string `json:"worker_id"`
		TaskID   uint   `json:"task_id"`
	}
}

func (req *CheckInstanceRequest) Validity(resp *CheckInstanceResponse) {
	if req.Request.WorkerID == "" || req.Request.TaskType == "" {
		resp.Code = errcode.ErrCode_BadRequest
		resp.Message = "参数错误"
	}
}

// CheckInstanceResponse 健康检查实例
type CheckInstanceResponse struct {
	apiobj.BaseResponse
}

// GetInstanceInfoRequest 健康检查实例
type GetInstanceInfoRequest struct {
	apiobj.BaseRequest
}

// GetInstanceInfoResponse 健康检查实例
type GetInstanceInfoResponse struct {
	apiobj.BaseResponse
	Response struct {
		InstanceInfo map[string]int64 `json:"instance_info"`
	}
}

// CommonPayload 通用任务负载
type CommonPayload struct {
	TaskType string `json:"task_type"` // 任务类型
	Timeout  int64  `json:"timeout"`   // 超时时间，单位秒
}
