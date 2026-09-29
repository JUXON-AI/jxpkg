package task

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/JUXON-AI/jxpkg/dbtools"
	"github.com/JUXON-AI/jxpkg/logs"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

// 自定义 Logger，设置日志级别为 Silent 不刷屏信息
var customLogger = logger.New(
	log.New(os.Stdout, "\r\n", log.LstdFlags), // 日志输出目标
	logger.Config{
		LogLevel: logger.Silent, // 设置日志级别
	},
)

// InitTaskDBStauts 初始化数据库中的任务状态
func InitTaskDBStauts() {
	ctx := context.TODO()
	logs.InfoContextf(ctx, "Start initializing database")
	err := dbtools.Core().Model(&Task{}).Where("task_status IN (?)", []TaskStatus{TaskStatusRunning}).
		Updates(map[string]interface{}{
			"task_status": TaskStatusFail,
			"redo":        gorm.Expr("redo + 1"), // 将 redo 字段的值加 1
		}).Error
	if err != nil {
		logs.ErrorContextf(ctx, "Update error:", err)
	} else {
		logs.InfoContextf(ctx, "InitTaskDBStauts successful")
	}
}

// readyTaskJoin computes the first unfinished step once per group. The former
// correlated NOT EXISTS rescanned the task table for every pending candidate
// without an appropriate deployment index. This is the same dependency rule,
// including negative steps and exhausted failures, with one grouped scan.
//
// # Why the inner scan steers away from one index
//
// The deployment's `idx_core_task_dependency (subject_id, app_group, step, deleted_at,
// task_status)` is the one shape that answers this subquery in a single pass: its leading
// columns satisfy the GROUP BY and the MIN(step) in index order, and its trailing ones
// carry the filter, so the whole thing is a covering scan with neither a temporary table
// nor a sort. The optimizer does not pick it on its own -- it prefers the single-column
// `deleted_at` index, which reaches the same rows but costs a row lookup each and then
// sorts them (EXPLAIN: "Using index condition; Using where; Using temporary; Using
// filesort", 13.4k rows on a 29.7k-row table). Naming that index as one to ignore is what
// moves the plan.
//
// IGNORE and not FORCE, and that is the safety half of the choice. FORCE INDEX fails with
// error 1176 on a deployment where schema/20260929-task-throughput.sql has not been
// applied, which would stop every claim on the platform instead of making it slow. What
// this ignores is the index the plan without the hint already uses, so a deployment where
// that one is absent was not using it either: the blast radius of this line is a plan
// choice, never a refusal.
const readyTaskJoin = "JOIN (SELECT subject_id, app_group, MIN(step) AS ready_step FROM core_task IGNORE INDEX (idx_core_task_deleted_at) WHERE deleted_at IS NULL AND task_status NOT IN ('cancel', 'success') GROUP BY subject_id, app_group) ready ON ready.subject_id = core_task.subject_id AND ready.app_group = core_task.app_group AND ready.ready_step = core_task.step"

// GetOnePendingTask 获取一个待处理的任务并标记为 Running
func GetOnePendingTask(task_type, worker_id string) (*Task, error) {
	return claimPendingTask(context.Background(), dbtools.Core(), task_type, worker_id)
}

// claimCandidateBatch bounds work when other workers claim the same leading IDs.
const claimCandidateBatch = 32

func claimPendingTask(ctx context.Context, db *gorm.DB, taskType, workerID string) (*Task, error) {
	// Bound one claim by time, not by a fixed prefix of the queue: a long
	// transaction may lock many leading rows while later work remains runnable.
	// Expiry is an error, distinct from an actually empty eligible queue.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Sorting an unindexed queue under FOR UPDATE locks scanned rows that will
	// never be returned. Discover candidates without locks, then lock by primary key.
	var attempted []uint
	for {
		var ids []uint
		query := db.WithContext(ctx).Model(&Task{}).Select("core_task.id").
			Where("task_type = ?", taskType).
			Where("task_status IN ?", []TaskStatus{TaskStatusPending, TaskStatusFail}).
			Where("redo <= task_config_redo").Joins(readyTaskJoin)
		if len(attempted) > 0 {
			query = query.Where("core_task.id NOT IN ?", attempted)
		}
		err := query.Order("priority DESC, updated_at ASC, core_task.id ASC").Limit(claimCandidateBatch).Pluck("core_task.id", &ids).Error
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			tsk, err := claimCandidate(ctx, db, id, taskType, workerID)
			if err != nil || tsk != nil {
				return tsk, err
			}
		}
		if len(ids) < claimCandidateBatch {
			break
		}
		attempted = append(attempted, ids...)
	}

	return nil, nil
}

func claimCandidate(ctx context.Context, db *gorm.DB, id uint, taskType, workerID string) (*Task, error) {
	tx := db.WithContext(ctx).Session(&gorm.Session{Logger: customLogger}).Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer tx.Rollback()
	var tsk Task
	err := tx.Omit("result").Where("id = ? AND task_type = ?", id, taskType).
		Where("task_status IN ?", []TaskStatus{TaskStatusPending, TaskStatusFail}).
		Where("redo <= task_config_redo").
		Clauses(clause.Locking{Strength: "UPDATE", Options: clause.LockingOptionsSkipLocked}).First(&tsk).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// This is the short transaction's first consistent read. Recheck dependencies
	// after locking: the unlocked candidate list may already be stale.
	var blocker struct{ ID uint }
	dependency := tx.Model(&Task{}).Select("id").
		Where("subject_id = ? AND app_group = ? AND step < ?", tsk.SubjectID, tsk.AppGroup, tsk.Step).
		Where("task_status NOT IN ?", []TaskStatus{TaskStatusCancel, TaskStatusSuccess}).Limit(1).Find(&blocker)
	if dependency.Error != nil {
		return nil, dependency.Error
	}
	if dependency.RowsAffected != 0 {
		return nil, nil
	}
	now := time.Now()
	tsk.TaskStatus, tsk.StartAt, tsk.WorkerID = TaskStatusRunning, &now, workerID
	tsk.EndAt, tsk.Cost = nil, 0
	if err := tx.Model(&Task{}).Where("id = ?", tsk.ID).Updates(map[string]interface{}{
		"task_status": TaskStatusRunning, "start_at": now, "worker_id": workerID, "end_at": nil, "cost": 0,
	}).Error; err != nil {
		return nil, err
	}
	if err := tx.Commit().Error; err != nil {
		return nil, err
	}
	return &tsk, nil
}

// GetTaskByID 根据id获取任务
func GetTaskByID(id uint) (*Task, error) {
	var tsk *Task
	err := dbtools.Core().Where("id = ?", id).First(&tsk).Error
	if err != nil {
		return nil, err
	}
	return tsk, nil
}

// GetTaskByIDAndWorkerID 根据id获取任务
func GetTaskByIDAndWorkerID(id uint, worker_id string) (*Task, error) {
	var tsk *Task
	err := dbtools.Core().Where("id = ?", id).
		Where("worker_id = ?", worker_id).
		// Where("task_status = ?", TaskStatusRunning).
		First(&tsk).Error
	if err != nil {
		return nil, err
	}
	return tsk, nil
}

// SaveTask 保存任务
func SaveTask(tsk *Task) error {
	if tsk.StartAt != nil && tsk.EndAt != nil {
		if tsk.StartAt.Before(*tsk.EndAt) {
			// 获取任务耗时
			tsk.Cost = int64(tsk.EndAt.Sub(*tsk.StartAt).Seconds())
		}
	}
	if tsk.TaskStatus == TaskStatusFail {
		tsk.Redo++
	}
	err := dbtools.Core().Save(tsk).Error
	if err != nil {
		return err
	}
	if tsk.TaskStatus == TaskStatusFail && tsk.Redo <= tsk.TaskConfigRedo {
		err = PushTaskQueue(context.Background(), tsk.TaskType)
		if err != nil {
			return err
		}
	}
	return nil
}

// finishClaim only persists an outcome while the same claim still owns the row.
// Payload and scheduling identity are immutable here; rewriting them resends
// megabytes and can overwrite a concurrent cancellation. start_at fences a
// claim reclaimed between the callback lookup and its conditional update.
func finishClaim(ctx context.Context, db *gorm.DB, tsk *Task) (bool, error) {
	if tsk.StartAt == nil || tsk.EndAt == nil {
		return false, errors.New("task outcome has no claim timestamps")
	}
	if tsk.StartAt.Before(*tsk.EndAt) {
		tsk.Cost = int64(tsk.EndAt.Sub(*tsk.StartAt).Seconds())
	}
	if tsk.TaskStatus == TaskStatusFail {
		tsk.Redo++
	}
	result := db.WithContext(ctx).Model(&Task{}).
		Where("id = ? AND worker_id = ? AND start_at = ? AND task_status = ?", tsk.ID, tsk.WorkerID, tsk.StartAt, TaskStatusRunning).
		Updates(map[string]interface{}{
			"task_status": tsk.TaskStatus, "result": tsk.Result, "err_msg": tsk.ErrMsg,
			"end_at": tsk.EndAt, "cost": tsk.Cost, "redo": tsk.Redo, "priority": tsk.Priority,
		})
	return result.RowsAffected == 1, result.Error
}

// CancelTask 取消任务
func CancelTask(tsk *Task) error {
	tsk.TaskStatus = TaskStatusCancel
	tsk.ErrMsg = "task cancelled"
	err := dbtools.Core().Save(tsk).Error
	if err != nil {
		return err
	}
	return nil
}

// CheckAndTimeoutTasks 检查任务是否超时
func CheckAndTimeoutTasks() {
	now := time.Now()
	ctx := context.TODO()
	var timeoutIDs []uint
	db := dbtools.Core().Session(&gorm.Session{Logger: customLogger})
	// jia锁查询
	var tasks []*Task
	err := db.
		Where("task_status = ?", TaskStatusRunning).
		Find(&tasks).Error
	if err != nil {
		logs.ErrorContextf(ctx, "Failed to query tasks: %v", err)
		return
	}
	for _, task := range tasks {
		timeoutTime := task.StartAt.Add(task.TaskConfigTimeout)
		if now.After(timeoutTime) {
			timeoutIDs = append(timeoutIDs, task.ID)
		}
	}
	if len(timeoutIDs) > 0 {
		// 在事务中批量更新状态为 timeout
		err = dbtools.Core().Model(&Task{}).
			Where("id IN ?", timeoutIDs).
			Where("task_status = ?", TaskStatusRunning).
			Updates(
				map[string]interface{}{
					"task_status": TaskStatusFail,
					"err_msg":     TaskStatusTimeout,
					"redo":        gorm.Expr("redo + 1"),
				},
			).Error

		if err != nil {
			logs.ErrorContextf(ctx, "Failed to update timeout tasks: %v", err)
			return
		}
		logs.InfoContextf(ctx, "Marked %d tasks as 'timeout' at %s", len(timeoutIDs), now)
	}
}

// DeleteTask 删除任务
func DeleteTask(id uint) error {
	ctx := context.TODO()
	err := dbtools.Core().WithContext(ctx).Where("id = ?", id).Delete(&Task{}).Error
	if err != nil {
		logs.ErrorContextf(ctx, "delete task failed, %s", err)
		return err
	}
	return nil
}

// validateNewTask 校验一条待创建的任务，不合法时返回拒绝原因。
//
// CreateTask 与 CreateTasks 共用这一处检查：两条路径的拒绝条件必须逐字一致，
// 否则批量创建会接受逐条创建拒绝的任务（或反过来），调用方无法在两者之间安全切换。
func validateNewTask(tsk *Task) error {
	if tsk == nil {
		return errors.New("task is nil")
	}
	if tsk.AppGroup == "" {
		return errors.New("app_group cannot be empty")
	}
	if tsk.SubjectID == 0 {
		return errors.New("subject_id cannot be zero")
	}
	if tsk.TaskType == "" {
		return errors.New("task_type cannot be empty")
	}
	if tsk.Payload == "" {
		return errors.New("payload cannot be empty")
	}
	if tsk.TaskConfigTimeout <= 0 {
		return errors.New("task_config_timeout must be greater than zero")
	}
	if tsk.TaskConfigRedo < 0 {
		return errors.New("task_config_redo cannot be negative")
	}
	return nil
}

// CreateTask 创建任务
func CreateTask(ctx context.Context, tsk *Task) error {
	if err := validateNewTask(tsk); err != nil {
		return err
	}
	err := dbtools.Core().Create(tsk).Error
	if err != nil {
		return err
	}
	return PushTaskQueue(ctx, tsk.TaskType)
}

// CreateTasks 批量创建任务。
//
// 与逐条调用 CreateTask 语义相同——同一套拒绝条件，同样把数据库分配的 id 写回入参
// （tasks 是 []*Task，故调用方持有切片即可读到 id），同样为每条任务推一次队列唤醒。
// 区别只在实现：一次批插入取代 N 次单条插入，一次 pipeline 取代 N 次 XADD。
//
// 全有全无：任意一条不合法都在写库之前返回，错误里带上它的下标，此时一条任务都没有落库。
// 生产者需要这个性质——一次扇出建出的任务是有依赖关系的（同一张图的定位任务与 embedding
// 任务，下游按张计数收口），部分成功会让计数永远等不到缺的那几条，而补数只能靠删掉已写入
// 的行重来。
//
// 原子性来自 dbtools 给每个连接配的 CreateBatchSize（200，见 dbtools/datasource.go）：
// 因为它是正数，dbtools.Core().Create 实际分派到 gorm 的 CreateInBatches，而后者在条数
// 超过批大小时用 tx.Transaction 把全部批次裹在一起——超过 200 条时发出去的不是一条多行
// INSERT 而是多条，但要么全提交要么全回滚。若哪天有人把 CreateBatchSize 去掉，Create
// 会退回单条语句的路径，原子性还在；真正的风险是把 SkipDefaultTransaction 打开，
// 那会让 CreateInBatches 走无事务分支，届时本函数的承诺不再成立。
//
// 调用方不要拿它承载没有共同失败语义的任务：整批共用一个事务，一条坏数据会让整批回滚。
func CreateTasks(ctx context.Context, tasks []*Task) error {
	return createTasks(ctx, tasks, func() *gorm.DB { return dbtools.Core() }, pushTaskQueues)
}

// The persistence and notification boundaries are separate: once the rows
// commit, a notification outage must not turn a caller retry into duplicate work.
func createTasks(ctx context.Context, tasks []*Task, database func() *gorm.DB, wake func(context.Context, []string) error) error {
	if len(tasks) == 0 {
		return errors.New("tasks cannot be empty")
	}
	for at, tsk := range tasks {
		if err := validateNewTask(tsk); err != nil {
			return fmt.Errorf("tasks[%d]: %w", at, err)
		}
	}
	if err := database().WithContext(ctx).Create(tasks).Error; err != nil {
		return err
	}
	taskTypes := make([]string, 0, len(tasks))
	for _, tsk := range tasks {
		taskTypes = append(taskTypes, tsk.TaskType)
	}
	if err := wake(ctx, taskTypes); err != nil {
		// Rows are already durable. Reporting creation failure makes callers
		// recreate the whole batch. CheckQueueCount repairs missing wake-ups.
		logs.ErrorContextw(ctx, "task.CreateTasks wake failed", "task_count", len(tasks))
	}
	return nil
}

// GetNextStepTask returns newly unblocked tasks in a strictly later step.
// Peers already received their wake-ups at creation. Broadcasting them again
// on every callback produces quadratic queue traffic for independent tasks.
func GetNextStepTask(tsk *Task) ([]*Task, error) {
	return nextStepTasks(context.Background(), dbtools.Core(), tsk)
}

func nextStepTasks(ctx context.Context, db *gorm.DB, tsk *Task) ([]*Task, error) {
	var tasks []*Task
	err := db.WithContext(ctx).Model(&Task{}).Select("id", "task_type", "step").
		Where("subject_id = ? AND app_group = ? AND step > ?", tsk.SubjectID, tsk.AppGroup, tsk.Step).
		Where("task_status IN ?", []TaskStatus{TaskStatusPending, TaskStatusFail}).
		Where("redo <= task_config_redo").
		Where("NOT EXISTS (SELECT 1 FROM core_task t2 WHERE t2.subject_id = core_task.subject_id AND t2.app_group = core_task.app_group AND t2.step < core_task.step AND t2.deleted_at IS NULL AND t2.task_status NOT IN (?, ?))", TaskStatusCancel, TaskStatusSuccess).
		Order("step ASC, id ASC").Find(&tasks).Error
	if err != nil {
		return nil, fmt.Errorf("read unblocked task steps: %w", err)
	}
	return tasks, nil
}

// GetPendingTaskCount 获取待处理任务数量
func GetPendingTaskCount(ctx context.Context, task_type string) (int64, error) {
	var count int64
	err := dbtools.Core().WithContext(ctx).Model(&Task{}).
		Where("task_type = ?", task_type).
		Where("task_status IN (?)", []TaskStatus{TaskStatusPending, TaskStatusFail}).
		Where("redo <= task_config_redo").
		Joins(readyTaskJoin).
		Count(&count).Error
	if err != nil {
		return 0, err
	}
	return count, nil
}
