package task

import (
	"context"
	"fmt"
	"time"

	"github.com/JUXON-AI/jxpkg/lifecycle"
	"github.com/JUXON-AI/jxpkg/mutex"
)

const (
	rediskeyprefix   = "coretask:task:"
	heartbeatTimeout = 30 // 健康检查超时时间
)

type TaskTypeInfo struct {
	TaskType string
	CallBack func(ctx context.Context, tsk *Task) error
}

var callBackMap = map[string]*TaskTypeInfo{}

func GetCallBackMap() map[string]*TaskTypeInfo {
	return callBackMap
}

func GetCallBack(taskType string) (*TaskTypeInfo, error) {
	if _, ok := callBackMap[taskType]; !ok {
		return nil, fmt.Errorf("taskType %s not found", taskType)
	}
	return callBackMap[taskType], nil
}

// RegisterCallBack 注册任务回调函数
func RegisterCallBack(taskType string, callBack func(ctx context.Context, tsk *Task) error) {
	callBackMap[taskType] = &TaskTypeInfo{
		TaskType: taskType,
		CallBack: callBack,
	}
}

// InitTask 任务初始化，checkHealth 表示是否启动 Worker 健康检查。
func InitTask(checkHealth bool) {
	// 在启动 goroutine 前初始化选主实例，避免多个任务循环并发初始化。
	mutex.IsMaster()
	ctx := lifecycle.Std().Context()
	// 启动任务超时检查
	go doTimeOutJob(ctx)
	if checkHealth {
		// 启动健康检测
		go doHealthJob(ctx)
	}
}

// doTimeOutJob 超时检查
func doTimeOutJob(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if mutex.IsMaster() {
				CheckAndTimeoutTasks()
				CheckQueueCount(ctx)
			}
		}
	}
}

// doHealthJob 三秒查一次不健康任务
func doHealthJob(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if mutex.IsMaster() {
				ChackWockerHealth()
			}
		}
	}
}
