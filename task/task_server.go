package task

import (
	"time"

	"github.com/JUXON-AI/jxpkg/apis/errcode"
	"github.com/JUXON-AI/jxpkg/dbtools"
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
	tsk, err = claimPendingTask(ctx.Request.Context(), dbtools.Core(), req.Request.TaskType, req.Request.WorkerID)
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
	resp.Response.Attempt = int64(tsk.Redo) + 1
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
		logs.ErrorContextw(ctx.Request.Context(), "task.TaskCallBack lookup failed", "task_id", req.Request.TaskID)
		resp.Code = errcode.ErrCode_InternalError
		resp.Message = "task_get_task_failed_or_timeout" // 获取任务失败,或任务以超时
		return
	}
	// Redelivery after a lost response is an acknowledgement, not a second
	// application callback. A canceled or expired claim cannot be resurrected.
	if tsk.TaskStatus != TaskStatusRunning {
		return
	}
	claimed, err := claimCallback(ctx.Request.Context(), dbtools.Core(), tsk, req.Request.Attempt)
	if err != nil {
		logs.ErrorContextw(ctx.Request.Context(), "task.TaskCallBack claim failed", "task_id", tsk.ID)
		resp.Code = errcode.ErrCode_InternalError
		resp.Message = "task_claim_callback_failed"
		return
	}
	if !claimed {
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
			logs.ErrorContextw(ctx.Request.Context(), "task.TaskCallBack application failed", "task_id", tsk.ID, "task_type", tsk.TaskType)
			tsk.TaskStatus = TaskStatusFail
			tsk.ErrMsg = "task_application_callback_failed"
		}
	}
	if tsk.TaskStatus == TaskStatusFail {
		tsk.Priority -= 1
	}
	var saved bool
	saved, err = finishClaimFromStatus(ctx.Request.Context(), dbtools.Core(), tsk, TaskStatusCompleting)
	if err != nil {
		logs.ErrorContextw(ctx.Request.Context(), "task.TaskCallBack save failed", "task_id", tsk.ID)
		resp.Code = errcode.ErrCode_InternalError
		resp.Message = "task_save_task_failed" // 保存任务失败
		return
	}
	if !saved {
		return
	}
	SetRedis(tsk.TaskType, req.Request.WorkerID, 0)
	if tsk.TaskStatus == TaskStatusFail && tsk.Redo <= tsk.TaskConfigRedo {
		if err := PushTaskQueue(ctx.Request.Context(), tsk.TaskType); err != nil {
			logs.ErrorContextw(ctx.Request.Context(), "task.TaskCallBack retry wake failed", "task_id", tsk.ID)
		}
	}
	if tsk.TaskStatus == TaskStatusSuccess {
		// 检查有没有同组的下阶段任务加入队列
		tasks, err := nextStepTasks(ctx.Request.Context(), dbtools.Core(), tsk)
		if err != nil {
			logs.ErrorContextw(ctx.Request.Context(), "task.TaskCallBack next step failed", "task_id", tsk.ID)
			resp.Code = errcode.ErrCode_InternalError
			resp.Message = "task_get_next_task_failed" // 获取下阶段任务失败
			return
		}
		if len(tasks) > 0 {
			types := make([]string, len(tasks))
			for i, next := range tasks {
				types[i] = next.TaskType
			}
			if err := pushTaskQueues(ctx.Request.Context(), types); err != nil {
				logs.ErrorContextw(ctx.Request.Context(), "task.TaskCallBack wake failed", "task_id", tsk.ID, "count", len(types))
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
