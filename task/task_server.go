package task

import (
	"time"

	"github.com/JUXON-AI/jxpkg/apis/errcode"
	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/gin-gonic/gin"
)

// GetPendingTask 获取一个待执行的任务
func GetPendingTask(ctx *gin.Context, req *GetPendingTestRequest, resp *GetPendingTestResponse) {
	if req.Validity(resp); resp.Code != 0 {
		return
	}
	var (
		tsk   *Task
		err   error
		msgID string
	)
	// TODO：判断实例是否存在redis中
	SetRedis(req.Request.TaskType, req.Request.WorkerID, 0)
	for i := 0; i < 10; i++ {
		// 如果请求已取消，则直接返回
		select {
		case <-ctx.Request.Context().Done():
			logs.ErrorContextf(ctx, "GetPendingTest context done,task_type: %v, worker_id: %v,error: %v", req.Request.TaskType, req.Request.WorkerID, ctx.Request.Context().Err())
			resp.Code = errcode.ErrCode_InternalError
			resp.Message = "task_request_canceled" // 请求已取消
			return
		default:
			msgID, err = PopTaskQueue(ctx.Request.Context(), req.Request.TaskType, req.Request.WorkerID)
			if err != nil {
				logs.ErrorContextf(ctx, "GetPendingTest PopTaskQueue task_type: %v, worker_id: %v, error: %v", req.Request.TaskType, req.Request.WorkerID, err)
				resp.Code = errcode.ErrCode_InternalError
				resp.Message = "task_get_task_failed" // 获取任务失败
				return
			}
		}
		if msgID != "" {
			break
		}
		time.Sleep(time.Second * 5)
	}
	if msgID == "" {
		logs.InfoContextf(ctx, "GetPendingTest PopTaskQueue task_type: %v, worker_id: %v, no task", req.Request.TaskType, req.Request.WorkerID)
		resp.Code = errcode.ErrCode_NotFound
		resp.Message = "task_no_task" // 暂无任务
		return
	}
	if ctxDone(ctx) {
		logs.ErrorContextf(ctx, "GetPendingTest context done,task_type: %v, worker_id: %v,error: %v", req.Request.TaskType, req.Request.WorkerID, ctx.Request.Context().Err())
		resp.Code = errcode.ErrCode_InternalError
		resp.Message = "task_request_canceled" // 请求已取消
		return
	}
	tsk, err = GetOnePendingTask(req.Request.TaskType, req.Request.WorkerID)
	if err != nil {
		logs.ErrorContextf(ctx, "GetPendingTest GetOnePendingTask task_type: %v, worker_id: %v, error: %v", req.Request.TaskType, req.Request.WorkerID, err)
		resp.Code = errcode.ErrCode_InternalError
		resp.Message = "task_query_task_failed" // 查询任务失败
		PushTaskQueue(ctx.Request.Context(), req.Request.TaskType)
		return
	}
	if tsk == nil {
		logs.InfoContextf(ctx, "GetPendingTest GetOnePendingTask task nil task_type: %v, worker_id: %v", req.Request.TaskType, req.Request.WorkerID)
		return
	}

	SetRedis(req.Request.TaskType, req.Request.WorkerID, tsk.ID)
	resp.Response.TaskID = tsk.ID
	resp.Response.Payload = tsk.Payload
}

// TaskCallBack 回调
func TaskCallBack(ctx *gin.Context, req *TaskCallBackRequest, resp *TaskCallBackResponse) {
	if req.Validity(resp); resp.Code != 0 {
		return
	}
	logs.InfoContextf(ctx, "task callback task_id: %v, status: %v", req.Request.TaskID, req.Request.Status)
	tsk, err := GetTaskByIDAndWorkerID(req.Request.TaskID, req.Request.WorkerID)
	if err != nil {
		logs.ErrorContextf(ctx, "TaskCallBack GetTaskByID task_type: %v, worker_id: %v, resault : %v,error: %v", req.Request.TaskID, req.Request.WorkerID, req.Request.Result, err)
		resp.Code = errcode.ErrCode_InternalError
		resp.Message = "task_get_task_failed_or_timeout" // 获取任务失败,或任务以超时
		return
	}
	tsk.TaskStatus = req.Request.Status
	tsk.Result = req.Request.Result
	tsk.ErrMsg = req.Request.ErrorMessage
	now := time.Now()
	tsk.EndAt = &now
	tc, err := GetCallBack(tsk.TaskType)
	if err == nil {
		err := tc.CallBack(ctx, tsk)
		if err != nil {
			logs.ErrorContextf(ctx, "taskid %d, task_type: %d,callback err:%v", tsk.ID, tsk.TaskType, err)
			tsk.TaskStatus = TaskStatusFail
		}
	}
	if tsk.TaskStatus == TaskStatusFail {
		tsk.ErrMsg = req.Request.ErrorMessage
		tsk.Priority -= 1
	}
	err = SaveTask(tsk)
	if err != nil {
		logs.ErrorContextf(ctx, "TaskCallBack SaveTask task_type: %v, worker_id: %v, resault : %v,error: %v", req.Request.TaskID, req.Request.WorkerID, req.Request.Result, err)
		resp.Code = errcode.ErrCode_InternalError
		resp.Message = "task_save_task_failed" // 保存任务失败
		return
	}
	SetRedis(tsk.TaskType, req.Request.WorkerID, 0)
	if tsk.TaskStatus == TaskStatusSuccess {
		// 检查有没有同组的下阶段任务加入队列
		tasks, err := GetNextStepTask(tsk)
		if err != nil {
			logs.ErrorContextf(ctx, "TaskCallBack GetNextStepTask task_type: %v, worker_id: %v, resault : %v,error: %v", req.Request.TaskID, req.Request.WorkerID, req.Request.Result, err)
			resp.Code = errcode.ErrCode_InternalError
			resp.Message = "task_get_next_task_failed" // 获取下阶段任务失败
			return
		}
		for _, nextTask := range tasks {
			err = PushTaskQueue(ctx.Request.Context(), nextTask.TaskType)
			if err != nil {
				logs.ErrorContextf(ctx, "TaskCallBack PushTaskQueue task_type: %v, worker_id: %v, resault : %v,error: %v", req.Request.TaskID, req.Request.WorkerID, req.Request.Result, err)
				continue
			}
		}
	}
}

// TaskCheckQueueCount 回调
func TaskCheckQueueCount(ctx *gin.Context, req *GetPendingTestRequest, resp *GetPendingTestResponse) {
	CheckQueueCount(ctx.Request.Context())
}

func ctxDone(ctx *gin.Context) bool {
	select {
	case <-ctx.Request.Context().Done():
		return true
	default:
		return false
	}
}
