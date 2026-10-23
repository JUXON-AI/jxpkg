package task

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/apiobj"
	"github.com/JUXON-AI/jxpkg/apis/runtime/server"
	"github.com/JUXON-AI/jxpkg/credits"
	"github.com/JUXON-AI/jxpkg/dbtools"
	"github.com/JUXON-AI/jxpkg/requestid"
	"github.com/gin-gonic/gin"
)

// WorkerConfig 由应用显式加载并传入，SDK 不读取 settings 或环境变量。
type WorkerConfig struct {
	// Token 是至少32字符的可信 Worker 服务凭证，不是员工模型 Key。
	Token string `yaml:"token" json:"-"`
}

const workerTaskContextKey = "jxpkg.task.worker.claim"

type workerTaskLookup func(context.Context, uint, string, string) (*Task, error)

func lookupWorkerTask(ctx context.Context, id uint, workerID, taskType string) (*Task, error) {
	var row Task
	err := dbtools.Core().WithContext(ctx).Where("id = ? AND worker_id = ? AND task_type = ?", id, workerID, taskType).First(&row).Error
	return &row, err
}

// RegisterWorkerRoutes 注册独立 Worker 认证边界，保持现有 action 和任务协议。
// acquire 由业务校验员工有效性后领取连接；任务主体仅来自权威任务记录。
// cfg 在注册时固定，应用更新令牌后需重启；既有未使用此入口的路由不受影响。
// callers 必须显式绑定受信 URI SAN 与 taskType；缺失时拒绝注册，Bearer 不单独授权。
func RegisterWorkerRoutes(router *server.Router, service, taskType string, cfg WorkerConfig, acquire credits.AcquireFunc, callers ...WorkerCaller) error {
	if router == nil || service == "" || taskType == "" || len(cfg.Token) < 32 || len(cfg.Token) > 8192 || strings.ContainsAny(cfg.Token, " \t\r\n") || acquire == nil {
		return errors.New("task: invalid worker route configuration")
	}
	if err := validateWorkerCallers(taskType, callers); err != nil {
		return err
	}
	guard := authenticateWorker(taskType, cfg, lookupWorkerTask, callers...)
	bindModels := bindTaskExecution(acquire)
	router.Post(service+".GetPendingTask", guard, GetPendingTask)
	router.Post(service+".TaskCallBack", guard, bindModels, TaskCallBack)
	router.Post(service+".CheckInstance", guard, CheckInstance)
	router.Post(service+".AcquireTaskModelConnection", guard, bindModels, acquireTaskModelConnection(lookupWorkerTask))
	return nil
}

type workerTaskInput struct {
	Request struct {
		TaskID   uint   `json:"task_id"`
		WorkerID string `json:"worker_id"`
		Attempt  int64  `json:"attempt"`
		TaskType string `json:"task_type"`
	} `json:"request"`
}

func authenticateWorker(taskType string, cfg WorkerConfig, lookup workerTaskLookup, callers ...WorkerCaller) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		values := ctx.Request.Header.Values("Authorization")
		if len(values) != 1 || len(ctx.Request.Header.Values("Cookie")) != 0 || !strings.HasPrefix(values[0], "Bearer ") {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		provided := sha256.Sum256([]byte(strings.TrimPrefix(values[0], "Bearer ")))
		expected := sha256.Sum256([]byte(cfg.Token))
		if subtle.ConstantTimeCompare(provided[:], expected[:]) != 1 {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		// Bearer 只作第二层凭证；工作负载身份来自直接 mTLS 握手。
		if !authorizedWorkerCertificate(ctx.Request, taskType, callers) {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(ctx.Writer, ctx.Request.Body, 1<<20))
		if err != nil {
			ctx.AbortWithStatus(http.StatusBadRequest)
			return
		}
		ctx.Request.Body = io.NopCloser(bytes.NewReader(raw))
		var input workerTaskInput
		if json.Unmarshal(raw, &input) != nil || input.Request.WorkerID == "" || len(input.Request.WorkerID) > 255 {
			ctx.AbortWithStatus(http.StatusBadRequest)
			return
		}
		if input.Request.TaskType != "" && input.Request.TaskType != taskType {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		if (strings.HasSuffix(ctx.Request.URL.Path, ".GetPendingTask") || strings.HasSuffix(ctx.Request.URL.Path, ".CheckInstance")) && input.Request.TaskType != taskType {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		if input.Request.TaskID == 0 {
			if input.Request.TaskType != taskType {
				ctx.AbortWithStatus(http.StatusForbidden)
				return
			}
		} else {
			row, err := lookup(ctx.Request.Context(), input.Request.TaskID, input.Request.WorkerID, taskType)
			if err != nil || row == nil {
				ctx.AbortWithStatus(http.StatusForbidden)
				return
			}
			// Callback 的幂等和 attempt fencing 仍由现有任务服务负责。
			ctx.Set(workerTaskContextKey, row)
		}
		ctx.Next()
	}
}

func bindTaskExecution(acquire credits.AcquireFunc) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		value, exists := ctx.Get(workerTaskContextKey)
		row, ok := value.(*Task)
		if !exists || !ok || row == nil || acquire == nil {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		e, err := credits.NewExecution(credits.Subject{OrganizationID: row.OrganizationID, UserID: row.UserID}, acquire)
		if err != nil {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		ctx.Set(credits.ExecutionContextKey, e)
		base := requestid.WithContext(ctx.Request.Context(), requestid.FromContext(ctx))
		ctx.Request = ctx.Request.WithContext(credits.WithExecution(base, e))
		ctx.Next()
	}
}

func validateWorkerCallers(taskType string, callers []WorkerCaller) error {
	if len(callers) == 0 || len(callers) > 64 {
		return errors.New("task: invalid worker callers")
	}
	seen := map[string]bool{}
	for _, caller := range callers {
		u, err := url.Parse(caller.Principal)
		if err != nil || len(caller.Principal) > 512 || u.Scheme != "spiffe" || u.Host == "" || u.Path == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || caller.TaskType != taskType || seen[caller.Principal] {
			return errors.New("task: invalid worker callers")
		}
		seen[caller.Principal] = true
	}
	return nil
}

func authorizedWorkerCertificate(r *http.Request, taskType string, callers []WorkerCaller) bool {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return false
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if leaf == nil || len(leaf.URIs) != 1 || leaf.URIs[0] == nil {
		return false
	}
	for _, caller := range callers {
		if caller.TaskType == taskType && caller.Principal == leaf.URIs[0].String() {
			return true
		}
	}
	return false
}

// AcquireTaskModelConnectionRequest 是 Worker 对当前领取任务的凭证请求。
type AcquireTaskModelConnectionRequest struct {
	// BaseRequest 是 JX 请求信封。
	apiobj.BaseRequest
	// Request 只包含任务领取信息，不允许客户端指定员工。
	Request struct {
		// TaskID 是当前任务 ID。
		TaskID uint `json:"task_id"`
		// WorkerID 是当前执行实例。
		WorkerID string `json:"worker_id"`
		// Attempt 是当前领取序号。
		Attempt int64 `json:"attempt"`
	} `json:"request"`
}

// AcquireTaskModelConnectionResponse 返回只在执行内使用的模型连接。
type AcquireTaskModelConnectionResponse struct {
	// BaseResponse 是 JX 响应信封。
	apiobj.BaseResponse
	// Response 是本次执行的员工模型连接。
	Response credits.Connection `json:"response"`
}

func acquireTaskModelConnection(lookup workerTaskLookup) func(*gin.Context, *AcquireTaskModelConnectionRequest, *AcquireTaskModelConnectionResponse) {
	return func(ctx *gin.Context, req *AcquireTaskModelConnectionRequest, resp *AcquireTaskModelConnectionResponse) {
		ctx.Header("Cache-Control", "no-store")
		value, exists := ctx.Get(workerTaskContextKey)
		row, ok := value.(*Task)
		if !exists || !ok || !validClaim(row, req.Request.TaskID, req.Request.WorkerID, req.Request.Attempt, time.Now()) {
			resp.Code = http.StatusForbidden
			return
		}
		connection, err := credits.ConnectionFromContext(ctx.Request.Context())
		if err != nil {
			resp.Code = http.StatusServiceUnavailable
			if errors.Is(err, credits.ErrDenied) {
				resp.Code = http.StatusForbidden
			}
			return
		}
		// 领取可能等待网络；返回前重读，防止任务已取消、重新领取或变更主体。
		latest, err := lookup(ctx.Request.Context(), row.ID, row.WorkerID, row.TaskType)
		if err != nil || !validClaim(latest, row.ID, row.WorkerID, req.Request.Attempt, time.Now()) || !latest.StartAt.Equal(*row.StartAt) || latest.OrganizationID != row.OrganizationID || latest.UserID != row.UserID {
			resp.Code = http.StatusForbidden
			return
		}
		resp.Response = connection
	}
}

func validClaim(row *Task, id uint, workerID string, attempt int64, now time.Time) bool {
	return row != nil && id != 0 && row.ID == id && workerID != "" && row.WorkerID == workerID && attempt > 0 && attempt == int64(row.Redo)+1 && row.TaskStatus == TaskStatusRunning && (credits.Subject{OrganizationID: row.OrganizationID, UserID: row.UserID}).Validate() == nil && row.StartAt != nil && row.TaskConfigTimeout > 0 && now.Before(row.StartAt.Add(row.TaskConfigTimeout))
}
