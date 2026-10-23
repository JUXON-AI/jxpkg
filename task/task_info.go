package task

import (
	"time"

	"github.com/JUXON-AI/jxpkg/dbtools"
	"gorm.io/gorm"
)

// TaskStatus 是任务状态。
type TaskStatus string

const (
	TaskStatusPending TaskStatus = "pending"
	TaskStatusRunning TaskStatus = "running"
	// TaskStatusCompleting 表示任务回调已被一个请求抢占，业务回调正在执行。
	TaskStatusCompleting TaskStatus = "completing"
	TaskStatusSuccess    TaskStatus = "success"
	TaskStatusFail       TaskStatus = "fail"
	TaskStatusCancel     TaskStatus = "cancel"
	TaskStatusTimeout    TaskStatus = "timeout"
)

const TableNameCoreTask = "core_task"

// Task 单文件任务
type Task struct {
	gorm.Model

	// OrganizationID 与 UserID 共同标识任务的额度归属，由创建任务的业务保存。
	OrganizationID string `gorm:"column:organization_id;type:varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null;index:idx_core_task_member,priority:1;comment:任务所属组织" json:"organization_id"`

	// UserID 保留 Logto 全局用户 ID；Worker 不得从回调请求覆盖该字段。
	UserID string `gorm:"column:user_id;type:varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null;index:idx_core_task_member,priority:2;comment:任务所属用户" json:"user_id"`
	// SubjectID 主体ID
	SubjectID uint `gorm:"type:int;column:subject_id;not null;comment:subject id" json:"subject_id"`
	// Step 步骤
	Step int `gorm:"type:int;column:step;not null;comment:task step" json:"step"`
	// TaskType
	TaskType string `gorm:"type:varchar(32);column:task_type;not null;comment:task type" json:"task_type"`
	// Priority 优先级
	Priority int `gorm:"type:tinyint;column:priority;not null;comment:task priority" json:"priority"`
	// TaskStatus 任务状态
	TaskStatus TaskStatus `gorm:"type:varchar(12);column:task_status;not null;comment:task status" json:"task_status"`
	// Redo 重试次数
	Redo int `gorm:"type:int;column:redo;not null;comment:redo times for parsing" json:"redo"`
	// ErrMsg 错误信息
	ErrMsg string `gorm:"type:longtext;column:err_msg;comment:error message" json:"err_msg"`
	// Comment 任务备注
	Comment string `gorm:"type:varchar(255);column:comment;comment:comment for parse task" json:"comment"`

	// WorkerID 任务执行者ID
	WorkerID string `gorm:"type:varchar(255);column:worker_id;comment:worker id" json:"worker_id"`
	// StartAt 任务开始时间
	StartAt *time.Time `gorm:"type:datetime;column:start_at;comment:task start time" json:"start_at"`
	// EndAt 任务结束时间
	EndAt *time.Time `gorm:"type:datetime;column:end_at;comment:task end time" json:"end_at"`
	// Cost 耗时
	Cost int64 `gorm:"type:int;column:cost;comment:task cost" json:"cost"`
	// Payload 任务数据
	Payload string `gorm:"type:longtext;column:payload;comment:task payload" json:"payload"`
	// Result 任务结果
	Result string `gorm:"type:longtext;column:result;comment:task result" json:"result"`
	// AppGroup 任务分组
	AppGroup string `gorm:"type:varchar(32);column:app_group;comment:task app group" json:"app_group"`

	// TaskConfigRedo 重试配置
	TaskConfigRedo int `gorm:"type:int;column:task_config_redo;not null;default:0;comment:'任务配置重试次数'" json:"task_config_redo"`
	// TaskConfigTimeout 超时配置
	TaskConfigTimeout time.Duration `gorm:"type:bigint;column:task_config_timeout;not null;default:0;comment:'任务配置超时时间'" json:"task_config_timeout"`
}

// TableName 返回任务表名。
func (Task) TableName() string {
	return TableNameCoreTask
}

// TaskList 是任务列表。
type TaskList []Task

// InitDB 初始化任务表及其显式迁移索引。
func InitDB() error {
	db := dbtools.Core()
	if err := dbtools.InitModel(db, &Task{}); err != nil {
		return err
	}
	return ensureTaskIndexes(db)
}
