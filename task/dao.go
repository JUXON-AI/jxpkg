package task

import (
	"context"
	"fmt"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/apiobj"
	"github.com/JUXON-AI/jxpkg/logs"
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
		return fmt.Errorf("[TaskDao] Insert fail, entity is nil")
	}
	db := dao.DB(ctx).Table(dao.TableName())
	if err := db.Create(entity).Error; err != nil {
		return fmt.Errorf("[TaskDao] Insert fail, entity:%s, err: %v", logs.JSON(entity), err)
	}
	return nil
}

func (dao *TaskDao) BatchInsert(ctx context.Context, entityList TaskList) error {
	if len(entityList) == 0 {
		return fmt.Errorf("[TaskDao] BatchInsert fail, entityList is empty")
	}

	db := dao.DB(ctx).Table(dao.TableName())
	if err := db.Create(entityList).Error; err != nil {
		return fmt.Errorf("[TaskDao] BatchInsert fail, entityList:%s, err: %v", logs.JSON(entityList), err)
	}
	return nil
}

func (dao *TaskDao) UpdateByID(ctx context.Context, companyID, uin, id uint, entity *Task) error {
	db := dao.DB(ctx).Table(dao.TableName())
	if err := db.Where("company_id = ? AND uin = ? AND id = ?", companyID, uin, id).Updates(entity).Error; err != nil {
		return fmt.Errorf("[TaskDao] UpdateByID fail, id:%d, entity:%s: %w", id, logs.JSON(entity), err)
	}
	return nil
}

func (dao *TaskDao) UpdateMap(ctx context.Context, companyID, uin, id uint, updateMap map[string]interface{}) error {
	db := dao.DB(ctx).Table(dao.TableName())
	if err := db.Where("company_id = ? AND uin = ? AND id = ?", companyID, uin, id).Updates(updateMap).Error; err != nil {
		return fmt.Errorf("[TaskDao] UpdateMap fail, id:%d, updateMap:%s: %w", id, logs.JSON(updateMap), err)
	}
	return nil
}

func (dao *TaskDao) Delete(ctx context.Context, companyID, uin, id uint) error {
	db := dao.DB(ctx).Table(dao.TableName())
	updatedField := map[string]interface{}{
		"deleted_at": time.Now(),
	}
	if err := db.Where("company_id = ? AND uin = ? AND id = ?", companyID, uin, id).Updates(updatedField).Error; err != nil {
		return fmt.Errorf("[TaskDao] Delete fail, id:%d: %w", id, err)
	}
	return nil
}

func (dao *TaskDao) GetByID(ctx context.Context, companyID, uin, id uint) (*Task, error) {
	var entity Task
	db := dao.DB(ctx).Table(dao.TableName())
	if err := db.Where("company_id = ? AND uin = ? AND id = ?", companyID, uin, id).First(&entity).Error; err != nil {
		return nil, fmt.Errorf("[TaskDao] GetByID fail, id:%d: %w", id, err)
	}
	return &entity, nil
}

func (dao *TaskDao) GetByCond(ctx context.Context, cond *TaskCond) (*Task, error) {
	var entity Task
	db := dao.DB(ctx).Table(dao.TableName())

	db = dao.BuildCondition(db, cond)

	if err := db.Find(&entity).Error; err != nil {
		return nil, fmt.Errorf("[TaskDao] GetByCond fail, cond:%s, err: %v", logs.JSON(cond), err)
	}
	return &entity, nil
}

func (dao *TaskDao) GetListByCond(ctx context.Context, cond *TaskCond) (TaskList, error) {
	var entityList TaskList
	db := dao.DB(ctx).Table(dao.TableName())

	db = dao.BuildCondition(db, cond)

	if err := db.Find(&entityList).Error; err != nil {
		return nil, fmt.Errorf("[TaskDao] GetListByCond fail, cond:%s, err: %v", logs.JSON(cond), err)
	}
	return entityList, nil
}

func (dao *TaskDao) GetPageListByCond(ctx context.Context, cond *TaskCond) (TaskList, int64, error) {
	db := dao.DB(ctx).Model(&Task{}).Table(dao.TableName())

	db = dao.BuildCondition(db, cond)

	var count int64
	if err := db.Count(&count).Error; err != nil {
		return nil, 0, fmt.Errorf("[TaskDao] GetPageListByCond count fail, cond:%s, err: %v", logs.JSON(cond), err)
	}
	if cond.Limit > 0 {
		db = db.Limit(cond.Limit)
	}
	if cond.Offset > 0 {
		db = db.Offset(cond.Offset)
	}
	var entityList TaskList
	if err := db.Find(&entityList).Error; err != nil {
		return nil, 0, fmt.Errorf("[TaskDao] GetPageListByCond find fail, cond:%s, err: %v", logs.JSON(cond), err)
	}
	return entityList, count, nil
}

func (dao *TaskDao) CountByCond(ctx context.Context, cond *TaskCond) (int64, error) {
	db := dao.DB(ctx).Model(&Task{}).Table(dao.TableName())

	db = dao.BuildCondition(db, cond)
	var count int64
	if err := db.Count(&count).Error; err != nil {
		return 0, fmt.Errorf("[TaskDao] CountByCond fail, cond:%s, err: %v", logs.JSON(cond), err)
	}
	return count, nil
}

// 平均耗时统计(秒)
func (dao *TaskDao) AvgCostTimeByCond(ctx context.Context, cond *TaskCond) (float64, error) {
	db := dao.DB(ctx).Model(&Task{}).Table(dao.TableName())
	db = dao.BuildCondition(db, cond)

	var avgCost float64
	if err := db.Select("COALESCE(AVG(cost), 0)").Scan(&avgCost).Error; err != nil {
		return 0, fmt.Errorf("[TaskDao] AvgCostTimeByCond fail, cond:%s, err: %v", logs.JSON(cond), err)
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
