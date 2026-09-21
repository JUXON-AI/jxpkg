package task

import (
	"context"
	"errors"
	"fmt"
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
	if len(tasks) == 0 {
		return errors.New("tasks cannot be empty")
	}
	for at, tsk := range tasks {
		if err := validateNewTask(tsk); err != nil {
			return fmt.Errorf("tasks[%d]: %w", at, err)
		}
	}
	if err := dbtools.Core().Create(tasks).Error; err != nil {
		return err
	}
	taskTypes := make([]string, 0, len(tasks))
	for _, tsk := range tasks {
		taskTypes = append(taskTypes, tsk.TaskType)
	}
	return pushTaskQueues(ctx, taskTypes)
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
