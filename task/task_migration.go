package task

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

const (
	_taskClaimIndexName            = "idx_core_task_claim"
	_taskMemberDependencyIndexName = "idx_core_task_member_dependency"
)

// taskClaimIndexMetadata exposes only the columns needed to compile the claim
// index. It must never be passed to AutoMigrate because its reduced field set is
// not a declaration of the core_task table.
type taskClaimIndexMetadata struct {
	TaskType   string     `gorm:"column:task_type;index:idx_core_task_claim,priority:1"`
	DeletedAt  *time.Time `gorm:"column:deleted_at;index:idx_core_task_claim,priority:2"`
	TaskStatus TaskStatus `gorm:"column:task_status;index:idx_core_task_claim,priority:3"`
	Priority   int        `gorm:"column:priority;index:idx_core_task_claim,priority:4"`
	UpdatedAt  time.Time  `gorm:"column:updated_at;index:idx_core_task_claim,priority:5"`
}

func (*taskClaimIndexMetadata) TableName() string {
	return TableNameCoreTask
}

// taskMemberDependencyIndexMetadata exposes only dependency columns. Member
// identity precedes the resource group so every consumer scans one member's
// tasks without sharing a cross-member readiness prefix.
type taskMemberDependencyIndexMetadata struct {
	OrganizationID string     `gorm:"column:organization_id;index:idx_core_task_member_dependency,priority:1"`
	UserID         string     `gorm:"column:user_id;index:idx_core_task_member_dependency,priority:2"`
	SubjectID      uint       `gorm:"column:subject_id;index:idx_core_task_member_dependency,priority:3"`
	AppGroup       string     `gorm:"column:app_group;index:idx_core_task_member_dependency,priority:4"`
	Step           int        `gorm:"column:step;index:idx_core_task_member_dependency,priority:5"`
	DeletedAt      *time.Time `gorm:"column:deleted_at;index:idx_core_task_member_dependency,priority:6"`
	TaskStatus     TaskStatus `gorm:"column:task_status;index:idx_core_task_member_dependency,priority:7"`
}

func (*taskMemberDependencyIndexMetadata) TableName() string {
	return TableNameCoreTask
}

// taskIndexStatistic carries the MySQL metadata that distinguishes a full
// ordinary B-tree column from a prefix, descending, unique, or special index.
type taskIndexStatistic struct {
	IndexName  string         `gorm:"column:INDEX_NAME"`
	ColumnName sql.NullString `gorm:"column:COLUMN_NAME"`
	NonUnique  int64          `gorm:"column:NON_UNIQUE"`
	SeqInIndex int            `gorm:"column:SEQ_IN_INDEX"`
	Collation  sql.NullString `gorm:"column:COLLATION"`
	SubPart    sql.NullInt64  `gorm:"column:SUB_PART"`
	IndexType  string         `gorm:"column:INDEX_TYPE"`
	IsVisible  sql.NullString `gorm:"column:IS_VISIBLE"`
}

// ensureTaskIndexes converges the explicitly migrated core_task indexes on the
// exact column order consumed by claims and member dependency scans. Existing
// same-name indexes are never dropped or overwritten, including the old
// subject/app-group dependency index retained from legacy deployments.
func ensureTaskIndexes(db *gorm.DB) error {
	statistics, err := readTaskIndexStatistics(db)
	if err != nil {
		return err
	}

	claimMetadata := &taskClaimIndexMetadata{}
	claimColumns, err := taskIndexColumns(db, claimMetadata, _taskClaimIndexName)
	if err != nil {
		return err
	}
	claimExists, err := validateExactTaskIndex(_taskClaimIndexName, claimColumns, statistics)
	if err != nil {
		return err
	}

	dependencyMetadata := &taskMemberDependencyIndexMetadata{}
	dependencyColumns, err := taskIndexColumns(db, dependencyMetadata, _taskMemberDependencyIndexName)
	if err != nil {
		return err
	}
	dependencyExists, err := validateExactTaskIndex(_taskMemberDependencyIndexName, dependencyColumns, statistics)
	if err != nil {
		return err
	}

	if !claimExists {
		if err := createTaskIndex(db, claimMetadata, _taskClaimIndexName); err != nil {
			return err
		}
	}
	if !dependencyExists {
		if err := createTaskIndex(db, dependencyMetadata, _taskMemberDependencyIndexName); err != nil {
			return err
		}
	}
	return nil
}

func taskIndexColumns(db *gorm.DB, metadata interface{}, name string) ([]string, error) {
	statement := &gorm.Statement{DB: db}
	if err := statement.Parse(metadata); err != nil {
		return nil, fmt.Errorf("parse index metadata %s: %w", name, err)
	}
	index := statement.Schema.LookIndex(name)
	if index == nil {
		return nil, fmt.Errorf("index metadata %s is unavailable", name)
	}
	columns := make([]string, 0, len(index.Fields))
	for _, field := range index.Fields {
		columns = append(columns, field.DBName)
	}
	return columns, nil
}

func readTaskIndexStatistics(db *gorm.DB) (map[string][]taskIndexStatistic, error) {
	database := db.Migrator().CurrentDatabase()
	if database == "" {
		return nil, errors.New("read core_task index metadata: current database is unavailable")
	}

	var rows []taskIndexStatistic
	if err := db.Table("information_schema.STATISTICS").
		Where("TABLE_SCHEMA = ? AND TABLE_NAME = ?", database, TableNameCoreTask).
		Order("INDEX_NAME ASC, SEQ_IN_INDEX ASC").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("read core_task index metadata: %w", err)
	}

	byName := make(map[string][]taskIndexStatistic, 2)
	for _, row := range rows {
		byName[row.IndexName] = append(byName[row.IndexName], row)
	}
	return byName, nil
}

func validateExactTaskIndex(name string, columns []string, statistics map[string][]taskIndexStatistic) (bool, error) {
	rows, found := statistics[name]
	if !found {
		return false, nil
	}
	if len(rows) != len(columns) {
		return false, fmt.Errorf("index %s has columns %v; want %v", name, statisticColumns(rows), columns)
	}
	for at, row := range rows {
		if !row.ColumnName.Valid {
			return false, fmt.Errorf("index %s column %d is not a full column", name, at+1)
		}
		if row.ColumnName.String != columns[at] {
			return false, fmt.Errorf("index %s has columns %v; want %v", name, statisticColumns(rows), columns)
		}
		if row.SeqInIndex != at+1 {
			return false, fmt.Errorf("index %s has sequence %d at position %d", name, row.SeqInIndex, at+1)
		}
		if row.NonUnique != 1 {
			return false, fmt.Errorf("index %s is unique; want a non-unique index", name)
		}
		if row.IndexType != "BTREE" {
			return false, fmt.Errorf("index %s type is %s; want BTREE", name, row.IndexType)
		}
		if row.IsVisible.Valid && row.IsVisible.String != "YES" {
			return false, fmt.Errorf("index %s is hidden", name)
		}
		if !row.Collation.Valid || row.Collation.String != "A" {
			return false, fmt.Errorf("index %s does not use ascending column order", name)
		}
		if row.SubPart.Valid {
			return false, fmt.Errorf("index %s uses a column prefix", name)
		}
	}
	return true, nil
}

func statisticColumns(rows []taskIndexStatistic) []string {
	columns := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.ColumnName.Valid {
			columns = append(columns, row.ColumnName.String)
		}
	}
	return columns
}

func createTaskIndex(db *gorm.DB, metadata interface{}, name string) error {
	if err := db.Migrator().CreateIndex(metadata, name); err != nil {
		return fmt.Errorf("create index %s: %w", name, err)
	}
	return nil
}
