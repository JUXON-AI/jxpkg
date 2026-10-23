package task

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/apiobj"
	"github.com/JUXON-AI/jxpkg/identity"
	"gorm.io/gorm"
)

type TaskCond struct {
	BaseCond
	Filters    []apiobj.Filter
	ID         uint
	IDs        []uint
	TaskType   string
	TaskStatus TaskStatus
}

type TaskDao struct {
	BaseModel
}

func NewTaskDao() *TaskDao {
	return &TaskDao{}
}

func (dao *TaskDao) TableName() string {
	return TableNameCoreTask
}

func (dao *TaskDao) WithTx(db *gorm.DB) *TaskDao {
	return &TaskDao{
		BaseModel: BaseModel{DBClient: db},
	}
}

func (dao *TaskDao) Insert(ctx context.Context, entity *Task) error {
	if entity == nil {
		return errors.New("task entity is required")
	}
	if err := validateNewTask(entity); err != nil {
		return fmt.Errorf("[TaskDao] Insert fail: %w", err)
	}
	db := dao.DB(ctx).Table(dao.TableName())
	if err := db.Create(entity).Error; err != nil {
		return fmt.Errorf("insert task: %w", err)
	}
	return nil
}

func (dao *TaskDao) BatchInsert(ctx context.Context, entityList TaskList) error {
	if len(entityList) == 0 {
		return errors.New("task batch is required")
	}
	for index := range entityList {
		if err := validateNewTask(&entityList[index]); err != nil {
			return fmt.Errorf("[TaskDao] BatchInsert fail, entityList[%d]: %w", index, err)
		}
	}

	db := dao.DB(ctx).Table(dao.TableName())
	if err := db.Create(entityList).Error; err != nil {
		return fmt.Errorf("insert task batch: %w", err)
	}
	return nil
}

func (dao *TaskDao) UpdateByID(ctx context.Context, organizationID, userID string, id uint, entity *Task) error {
	db := taskMemberQuery(dao.DB(ctx).Table(dao.TableName()), organizationID, userID).Where("id = ?", id)
	if err := db.Omit("id", "organization_id", "user_id").Updates(entity).Error; err != nil {
		return fmt.Errorf("update task %d: %w", id, err)
	}
	return nil
}

func (dao *TaskDao) UpdateMap(ctx context.Context, organizationID, userID string, id uint, updateMap map[string]interface{}) error {
	db := taskMemberQuery(dao.DB(ctx).Table(dao.TableName()), organizationID, userID).Where("id = ?", id)
	if err := db.Omit("id", "organization_id", "user_id").Updates(updateMap).Error; err != nil {
		return fmt.Errorf("update task fields %d: %w", id, err)
	}
	return nil
}

func (dao *TaskDao) Delete(ctx context.Context, organizationID, userID string, id uint) error {
	db := taskMemberQuery(dao.DB(ctx).Table(dao.TableName()), organizationID, userID).Where("id = ?", id)
	updatedField := map[string]interface{}{
		"deleted_at": time.Now(),
	}
	if err := db.Updates(updatedField).Error; err != nil {
		return fmt.Errorf("[TaskDao] Delete fail, id:%d: %w", id, err)
	}
	return nil
}

func (dao *TaskDao) GetByID(ctx context.Context, organizationID, userID string, id uint) (*Task, error) {
	var entity Task
	db := taskMemberQuery(dao.DB(ctx).Table(dao.TableName()), organizationID, userID).Where("id = ?", id)
	if err := db.First(&entity).Error; err != nil {
		return nil, fmt.Errorf("[TaskDao] GetByID fail, id:%d: %w", id, err)
	}
	return &entity, nil
}

func taskMemberQuery(db *gorm.DB, organizationID, userID string) *gorm.DB {
	if (identity.Member{OrganizationID: organizationID, UserID: userID}).Validate() != nil {
		return db.Where("1 = 0")
	}
	return db.Where("organization_id = ? AND user_id = ?", organizationID, userID)
}

func (dao *TaskDao) GetByCond(ctx context.Context, cond *TaskCond) (*Task, error) {
	var entity Task
	db := dao.DB(ctx).Table(dao.TableName())

	db = dao.BuildCondition(db, cond)

	if err := db.Find(&entity).Error; err != nil {
		return nil, fmt.Errorf("find task: %w", err)
	}
	return &entity, nil
}

func (dao *TaskDao) GetListByCond(ctx context.Context, cond *TaskCond) (TaskList, error) {
	var entityList TaskList
	db := dao.DB(ctx).Table(dao.TableName())

	db = dao.BuildCondition(db, cond)

	if err := db.Find(&entityList).Error; err != nil {
		return nil, fmt.Errorf("list tasks: %w", err)
	}
	return entityList, nil
}

func (dao *TaskDao) GetPageListByCond(ctx context.Context, cond *TaskCond) (TaskList, int64, error) {
	db := dao.DB(ctx).Model(&Task{}).Table(dao.TableName())

	db = dao.BuildCondition(db, cond)

	var count int64
	if err := db.Count(&count).Error; err != nil {
		return nil, 0, fmt.Errorf("count task page: %w", err)
	}
	if cond.Limit > 0 {
		db = db.Limit(cond.Limit)
	}
	if cond.Offset > 0 {
		db = db.Offset(cond.Offset)
	}
	var entityList TaskList
	if err := db.Find(&entityList).Error; err != nil {
		return nil, 0, fmt.Errorf("list task page: %w", err)
	}
	return entityList, count, nil
}

func (dao *TaskDao) CountByCond(ctx context.Context, cond *TaskCond) (int64, error) {
	db := dao.DB(ctx).Model(&Task{}).Table(dao.TableName())

	db = dao.BuildCondition(db, cond)
	var count int64
	if err := db.Count(&count).Error; err != nil {
		return 0, fmt.Errorf("count tasks: %w", err)
	}
	return count, nil
}

// 平均耗时统计(秒)
func (dao *TaskDao) AvgCostTimeByCond(ctx context.Context, cond *TaskCond) (float64, error) {
	db := dao.DB(ctx).Model(&Task{}).Table(dao.TableName())
	db = dao.BuildCondition(db, cond)

	var avgCost float64
	if err := db.Select("COALESCE(AVG(cost), 0)").Scan(&avgCost).Error; err != nil {
		return 0, fmt.Errorf("average task cost: %w", err)
	}
	return avgCost, nil
}

func (dao *TaskDao) BuildCondition(db *gorm.DB, cond *TaskCond) *gorm.DB {
	db = dao.BaseModel.BuildBaseCondition(db, dao.TableName(), cond.BaseCond)
	if cond.ID > 0 {
		query := fmt.Sprintf("%s.id = ?", dao.TableName())
		db = db.Where(query, cond.ID)
	}
	if len(cond.IDs) > 0 {
		query := fmt.Sprintf("%s.id in ?", dao.TableName())
		db = db.Where(query, cond.IDs)
	}
	if cond.TaskType != "" {
		query := fmt.Sprintf("%s.task_type = ?", dao.TableName())
		db = db.Where(query, cond.TaskType)
	}
	if cond.TaskStatus != "" {
		query := fmt.Sprintf("%s.task_status = ?", dao.TableName())
		db = db.Where(query, cond.TaskStatus)
	}
	return db
}
