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
	TaskStatusSuccess TaskStatus = "success"
	TaskStatusFail    TaskStatus = "fail"
	TaskStatusCancel  TaskStatus = "cancel"
	TaskStatusTimeout TaskStatus = "timeout"
)

const TableNameCoreTask = "core_task"

// Task 单文件任务
type Task struct {
	gorm.Model

	// CompanyID 表示任务所属的公司 ID。
	CompanyID uint `gorm:"column:company_id;type:bigint unsigned;not null;default:0;index:idx_core_task_company_uin,priority:1;comment:任务所属公司ID" json:"company_id"`

	// UIN 表示任务所属的账户身份 ID。
	UIN uint `gorm:"column:uin;type:bigint unsigned;not null;default:0;index:idx_core_task_company_uin,priority:2;comment:任务所属账户身份ID" json:"uin"`
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

// InitDB 初始化任务表。
func InitDB() error {
	return dbtools.InitModel(dbtools.Core(), &Task{})
}
