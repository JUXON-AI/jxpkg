package task

import (
	"context"
	"errors"
	"log"
	"os"
	"sort"
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

// GetOnePendingTask 获取一个待处理的任务并标记为 Running
func GetOnePendingTask(task_type, worker_id string) (*Task, error) {
	var (
		tsk Task
		ctx = context.TODO()
	)
	db := dbtools.Core().Session(&gorm.Session{Logger: customLogger})
	// 开启事务
	tx := db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()
	// 加锁查询，排除 step 更小但未成功的任务
	err := tx.
		WithContext(ctx).
		Where("task_type = ?", task_type).
		Where("task_status IN (?)", []TaskStatus{TaskStatusPending, TaskStatusFail}).
		Where("redo <= task_config_redo").
		Where(`
			NOT EXISTS (
				SELECT 1 FROM core_task t2
				WHERE t2.subject_id = core_task.subject_id
				  AND t2.app_group = core_task.app_group
				  AND t2.step < core_task.step
				  AND t2.deleted_at IS NULL
			  AND t2.task_status NOT IN (?)
			)
		`, []TaskStatus{TaskStatusCancel, TaskStatusSuccess}).
		Order("priority DESC, updated_at ASC").
		Clauses(clause.Locking{Strength: "UPDATE", Options: clause.LockingOptionsSkipLocked}).
		First(&tsk).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			tx.Rollback()
			return nil, nil
		}
		logs.ErrorContextf(ctx, "Failed to find pending task: %v", err)
		tx.Rollback()
		return nil, err
	}
	now := time.Now()
	// 更新任务状态为 Running
	tsk.TaskStatus = TaskStatusRunning
	tsk.StartAt = &now
	tsk.WorkerID = worker_id
	err = tx.Save(&tsk).Error
	if err != nil {
		logs.ErrorContextf(ctx, "Failed to update task status to running: %v", err)
		tx.Rollback()
		return nil, err
	}
	// 提交事务
	tx.Commit()
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

// CreateTask 创建任务
func CreateTask(ctx context.Context, tsk *Task) error {
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
	err := dbtools.Core().Create(tsk).Error
	if err != nil {
		return err
	}
	return PushTaskQueue(ctx, tsk.TaskType)
}

// GetNextStepTask 获取下一个步骤的任务
func GetNextStepTask(tsk *Task) ([]*Task, error) {
	var allTasks []*Task
	ctx := context.TODO()
	err := dbtools.Core().Where("subject_id = ? AND app_group = ?", tsk.SubjectID, tsk.AppGroup).
		Order("step ASC").
		Find(&allTasks).Error
	if err != nil {
		logs.ErrorContextf(ctx, "GetNextStepTask error: %v", err)
		return nil, err
	}

	// 按 step 分组
	stepTaskMap := make(map[int][]*Task)
	stepSet := map[int]struct{}{}
	for _, task := range allTasks {
		stepTaskMap[task.Step] = append(stepTaskMap[task.Step], task)
		stepSet[task.Step] = struct{}{}
	}

	// 提取并排序所有 step
	var steps []int
	for step := range stepSet {
		steps = append(steps, step)
	}
	sort.Ints(steps)

	// 查找第一个未全部完成的 step
	for _, step := range steps {
		tasks := stepTaskMap[step]
		allCompleted := true
		for _, task := range tasks {
			if task.TaskStatus != TaskStatusSuccess {
				allCompleted = false
				break
			}
		}
		if !allCompleted {
			var result []*Task
			for _, task := range tasks {
				if task.TaskStatus == TaskStatusPending || task.TaskStatus == TaskStatusFail || task.TaskStatus == TaskStatusRunning {
					result = append(result, task)
				}
			}
			logs.InfoContextf(ctx, "Next incomplete step: %d, pending tasks: %d", step, len(result))
			return result, nil
		}
	}

	// 所有任务都完成了
	return nil, nil
}

// GetPendingTaskCount 获取待处理任务数量
func GetPendingTaskCount(ctx context.Context, task_type string) (int64, error) {
	var count int64
	err := dbtools.Core().WithContext(ctx).Model(&Task{}).
		Where("task_type = ?", task_type).
		Where("task_status IN (?)", []TaskStatus{TaskStatusPending, TaskStatusFail}).
		Where("redo <= task_config_redo").
		Where(`
			NOT EXISTS (
				SELECT 1 FROM core_task t2
				WHERE t2.subject_id = core_task.subject_id
				  AND t2.app_group = core_task.app_group
				  AND t2.step < core_task.step
				  AND t2.deleted_at IS NULL
			  AND t2.task_status NOT IN (?)
			)
		`, []TaskStatus{TaskStatusCancel, TaskStatusSuccess}).
		Count(&count).Error
	if err != nil {
		return 0, err
	}
	return count, nil
}
