package task

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/errcode"
	"github.com/JUXON-AI/jxpkg/dbtools/redispool"
	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/gin-gonic/gin"
)

// CheckInstance 健康检查实例
func CheckInstance(ctx *gin.Context, req *CheckInstanceRequest, resp *CheckInstanceResponse) {
	if req.Validity(resp); resp.Code != 0 {
		return
	}
	// 新注册的实例同级任务类型的实例数量
	_, err := SetRedis(req.Request.TaskType, req.Request.WorkerID, req.Request.TaskID)
	if err != nil {
		logs.ErrorContextf(ctx, "CheckInstance SetRedis error: %v,worker_id: %v,task_type: %v", err, req.Request.WorkerID, req.Request.TaskType)
		resp.Code = errcode.ErrCode_InternalError
		resp.Message = "task_register_instance_failed" // 注册实例失败
		return
	}
}

// GetInstanceInfo 获取当前注册的任务实例数量
func GetInstanceInfo(ctx *gin.Context, req *GetInstanceInfoRequest, resp *GetInstanceInfoResponse) {
	types, err := GetAllCoreTaskKeys()
	if err != nil {
		logs.ErrorContextf(ctx, "get task types error: %v", err)
		return
	}
	taskInstanceMap := make(map[string]int64, len(types))
	for _, item := range types {
		// 获取对应任务类型的实例数量
		count, err := LenTaskInstanceMap(item)
		if err != nil {
			logs.ErrorContextf(ctx, "GetInstanceInfo LenTaskInstanceMap error: %v,task_type: %v", err, item)
			resp.Code = errcode.ErrCode_InternalError
			resp.Message = "task_get_instance_count_failed" // 获取实例数量失败
			return
		}
		taskInstanceMap[item] = count
	}

	resp.Response.InstanceInfo = taskInstanceMap
}

// WriteAndFlushResponse 向响应流中写入健康检查响应
func WriteAndFlushHealthResponse(writer gin.ResponseWriter) error {
	// 将结构体序列化为 JSON
	jsonData, err := json.Marshal("healthy\n")
	if err != nil {
		return err
	}
	// 写入响应流
	if _, err := writer.Write(jsonData); err != nil {
		return err
	}
	_, err = writer.Write([]byte("\n"))
	if err != nil {
		return err
	}
	// 刷新响应流
	writer.(http.Flusher).Flush()
	return nil
}

// SetRedis 设置redis 更新心跳时间戳
func SetRedis(task_type, wockerid string, taskid uint) (int64, error) {
	timestamp := time.Now().Unix()
	res, err := redispool.CacheInstance().HSet(rediskeyprefix+task_type, wockerid, fmt.Sprintf("%v-%v", timestamp, taskid))
	if err != nil {
		return 0, err
	}
	return res, nil
}

// DeleteRedis 删除对应实例
func DeleteRedis(task_type, wockerid string) (int64, error) {
	res, err := redispool.CacheInstance().HDel(rediskeyprefix+task_type, wockerid)
	if err != nil {
		return 0, err
	}
	return res, nil
}

// LenTaskInstanceMap 获取对应任务类型的实例数量
func LenTaskInstanceMap(task_type string) (int64, error) {
	count, err := redispool.Redis().HLen(context.Background(), rediskeyprefix+task_type).Result()
	if err != nil {
		return 0, err
	}
	return count, nil
}

// GetAllCoreTaskKeys 获取任务类型
func GetAllCoreTaskKeys() ([]string, error) {
	var keys []string
	var cursor uint64
	var types []string

	for {
		// 扫描匹配的 key
		kk, nextCursor, err := redispool.Redis().Scan(context.Background(), cursor, rediskeyprefix+"*", 100).Result()
		if err != nil {
			return nil, err
		}

		keys = append(keys, kk...)
		cursor = nextCursor

		if cursor == 0 {
			break
		}
	}
	for _, key := range keys {
		// 提取任务类型
		if strings.HasPrefix(key, rediskeyprefix) {
			taskType := strings.TrimPrefix(key, rediskeyprefix)
			types = append(types, taskType)
		}
	}

	return types, nil
}

// ChackWockerHealth 检查worker是否已过期
func ChackWockerHealth() {
	now := time.Now().Unix()
	ctx := context.TODO()
	types, err := GetAllCoreTaskKeys()
	if err != nil {
		logs.ErrorContextf(ctx, "get task types error: %v", err)
		return
	}
	for _, item := range types {
		// key := rediskeyprefix + item.TaskType
		worckerMap, err := redispool.Redis().HGetAll(context.Background(), rediskeyprefix+item).Result()
		if err != nil {
			logs.ErrorContextf(ctx, "get workers error: %v, task_type: %v", err, item)
			continue
		}
		for worckerID, value := range worckerMap {
			parts := strings.Split(value, "-")
			if len(parts) < 2 {
				logs.WarnContextf(ctx, "invalid format for worker: %s:%s", worckerID, value)
				// 格式不对，删除wocker
				DeleteRedis(item, worckerID)
				continue
			}
			timestampStr := parts[0]
			timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
			if err != nil {
				logs.WarnContextf(ctx, "parse timestamp error: %v, worker: %s", err, worckerID)
				// 格式不对，删除wocker
				DeleteRedis(item, worckerID)
				continue
			}

			// 判断是否超时
			if now-timestamp > heartbeatTimeout {
				logs.InfoContextf(ctx, "worker expired: %s, task_type: %s, last heartbeat: %d", worckerID, item, timestamp)
				// 心跳超时删
				DeleteRedis(item, worckerID)
				// 心跳超时手动过期任务
				taskid, err := strconv.ParseUint(parts[1], 10, 64)
				if err != nil {
					logs.ErrorContextf(ctx, "get task error: %v, task_id: %v, worker_id: %v", err, taskid, worckerID)
					continue
				}
				if taskid == 0 {
					continue
				}
				task, err := GetTaskByIDAndWorkerID(uint(taskid), worckerID)
				if err != nil {
					// 没找到不用改
					logs.WarnContextf(ctx, "get task error: %v, task_id: %v, worker_id: %v", err, taskid, worckerID)
					continue
				}
				task.ErrMsg = "task_health_check_timeout" // health check timeout
				task.TaskStatus = TaskStatusFail
				now := time.Now()
				task.EndAt = &now
				SaveTask(task)
			}
		}
	}
}
