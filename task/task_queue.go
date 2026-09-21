package task

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/JUXON-AI/jxpkg/dbtools/redispool"
	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/redis/go-redis/v9"
)

const (
	TaskQueryPrefix = "coretask:task_queue:"
	TaskGroupPrefix = "coretask:task_group:"
)

// PushTaskQueue 将任务类型推入任务队列
func PushTaskQueue(ctx context.Context, taskType string) error {
	taskqueryid, err := redispool.Redis().XAdd(ctx, &redis.XAddArgs{
		Stream: TaskQueryPrefix + taskType,
		Values: map[string]interface{}{"task_type": taskType},
	}).Result()
	if err != nil {
		return err
	}
	logs.InfoContextf(ctx, "push task queue success, taskType: %s, taskqueryid: %s", taskType, taskqueryid)
	return nil
}

// pushTaskQueues 批量推入任务队列唤醒通知，每条任务一条。
//
// 逐条调用 PushTaskQueue 与它产生完全相同的 stream 内容，只是 N 次 XADD 走一次往返。
// 这里刻意不按类型去重：stream 里的消息不是任务本身而是「该类型有活」的唤醒信号，认领
// 从 core_task 读，所以条数不承担正确性；但 CheckQueueCount 会把 stream 长度补齐到待处理
// 任务数，去重省下的条数会被它在下一次扫描时逐条补回来，白省。
//
// 暂不导出：包外目前没有任何地方推队列（连单个的 PushTaskQueue 也没有包外调用者），
// 批量路径的入口是 CreateTasks。等真的出现绕过 CreateTasks 建行、需要自己唤醒的场景
// 再导出，那时才知道它该长什么样。
func pushTaskQueues(ctx context.Context, taskTypes []string) error {
	if len(taskTypes) == 0 {
		return errors.New("task types cannot be empty")
	}
	pipe := redispool.Redis().Pipeline()
	for _, taskType := range taskTypes {
		pipe.XAdd(ctx, &redis.XAddArgs{
			Stream: TaskQueryPrefix + taskType,
			Values: map[string]interface{}{"task_type": taskType},
		})
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return err
	}
	logs.InfoContextf(ctx, "push task queue batch success, count: %d", len(taskTypes))
	return nil
}

// PopTaskQueue 从任务队列中取出一个任务返回当前任务id
func PopTaskQueue(ctx context.Context, taskType, workerid string) (string, error) {
	// 创建消费组（如果不存在）
	stream := TaskQueryPrefix + taskType
	group := TaskGroupPrefix + taskType
	_ = redispool.Redis().XGroupCreateMkStream(ctx, stream, group, "$").Err()
	// 阻塞时收不到ctx.done 很短的阻塞时间去获取然后done断开
	res, err := redispool.Redis().XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    group,
		Consumer: workerid,
		Streams:  []string{stream, ">"},
		Count:    1,
		Block:    time.Millisecond * 100, // 阻塞100ms
		NoAck:    true,                   // 自动确认 不需要调用ack
	}).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// 空队列是 worker 长轮询的正常状态，只在 Debug 级别保留诊断信息。
			logs.DebugContextf(ctx, "no task, wait for next task, taskType: %s, workerid: %s", taskType, workerid)
			return "", nil
		}
		return "", err // 真正的错误
	}
	if len(res) > 0 && len(res[0].Messages) > 0 {
		return res[0].Messages[0].ID, nil
	}
	return "", fmt.Errorf("no task, wait for next task, taskType: %s, workerid: %s", taskType, workerid)
}

// TaskAck 确认消费任务
func TaskAck(ctx context.Context, taskType, msgID string) error {
	stream := TaskQueryPrefix + taskType
	group := TaskGroupPrefix + taskType
	err := redispool.Redis().XAck(ctx, stream, group, msgID).Err()
	if err != nil {
		return err
	}
	return nil
}

// CheckPendingMessages 检查未处理的任务消息超过一分钟未处理重新推入队列
func CheckPendingMessages(ctx context.Context, taskType string) (int, error) {
	stream := TaskQueryPrefix + taskType
	group := TaskGroupPrefix + taskType
	pending, err := redispool.Redis().XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream: stream,
		Group:  group,
		Start:  "-",
		End:    "+",
		Idle:   time.Minute, // 空闲时间为1分钟
	}).Result()
	if err != nil {
		return 0, err
	}
	for _, p := range pending {
		err = PushTaskQueue(ctx, taskType) // 重新推入任务队列
		if err != nil {
			continue
		}
		err := redispool.Redis().XAck(ctx, stream, group, p.ID).Err()
		if err != nil {
			continue
		}
	}
	return len(pending), nil
}

// GetStreamPendingLen 获取stream的pending消息数量
func GetStreamPendingLen(ctx context.Context, taskType string) (int, error) {
	stream := TaskQueryPrefix + taskType
	group := TaskGroupPrefix + taskType
	// 1. 获取 last-delivered-id
	groupInfo, err := redispool.Redis().XInfoGroups(ctx, stream).Result()
	if err != nil {
		return 0, fmt.Errorf("XINFO GROUPS error: %w", err)
	}

	var lastID string
	found := false
	for _, g := range groupInfo {
		if g.Name == group {
			lastID = g.LastDeliveredID
			found = true
			break
		}
	}
	if !found {
		return 0, fmt.Errorf("group '%s' not found", group)
	}

	// 2. 获取从 last-delivered-id 到末尾的消息数
	entries, err := redispool.Redis().XRangeN(ctx, stream, lastID, "+", 10000).Result()
	if err != nil {
		return 0, fmt.Errorf("XRANGE error: %w", err)
	}

	// 减掉起始ID自己
	count := len(entries)
	if count > 0 {
		count--
	}
	return count, nil
}

// CheckQueueCount 检查任务队列数量
func CheckQueueCount(ctx context.Context) {
	types, err := GetAllCoreTaskKeys()
	if err != nil {
		logs.ErrorContextf(ctx, "get task types error: %v", err)
		return
	}
	for _, t := range types {
		count, err := GetStreamPendingLen(ctx, t)
		if err != nil {
			logs.ErrorContextf(ctx, "Failed GetStreamPendingLen to push timeout task to queue: %v", err)
			continue
		}
		task_count, err := GetPendingTaskCount(ctx, t)
		if err != nil {
			logs.ErrorContextf(ctx, "Failed GetPendingTaskCount to push timeout task to queue: %v", err)
			continue
		}
		if count < int(task_count) {
			// 队列数量小于任务数量
			for i := 0; i < int(task_count)-count; i++ {
				err := PushTaskQueue(ctx, t)
				if err != nil {
					logs.ErrorContextf(ctx, "Failed PushTaskQueue to push timeout task to queue: %v", err)
					continue
				}
			}
		}
	}
}
