package dbtools

import (
	"github.com/JUXON-AI/jxpkg/logs"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// InitModelFunc 无参的模型初始化函数。
type InitModelFunc func() error

// InitModelWithDBFunc 接收 *gorm.DB 的模型初始化函数。
type InitModelWithDBFunc func(db *gorm.DB) error

// InitModel 对传入的模型依次执行 AutoMigrate。
func InitModel(db *gorm.DB, models ...interface{}) error {
	for _, v := range models {
		if err := db.AutoMigrate(v); err != nil {
			logs.Errorf("[init-db] auto migrate %T failed, %s", v, err)
			return err
		}
	}
	return nil
}

// DoInitModels 依次执行无参初始化函数。
func DoInitModels(imfs ...InitModelFunc) error {
	for _, imf := range imfs {
		if err := imf(); err != nil {
			logs.Errorf("[init-db] do %T failed, %s", imf, err)
			return err
		}
	}
	return nil
}

// DoInitModelsWithDB 依次执行带 *gorm.DB 参数的初始化函数。
func DoInitModelsWithDB(db *gorm.DB, imfs ...InitModelWithDBFunc) error {
	for _, imf := range imfs {
		if err := imf(db); err != nil {
			logs.Errorf("[init-db] do %T failed, %s", imf, err)
			return err
		}
	}
	return nil
}

// InsertOrUpdate 执行插入或更新（UPSERT）。columns 指定冲突时需更新的列。
func InsertOrUpdate(db *gorm.DB, v interface{}, columns ...string) error {
	return db.Clauses(clause.OnConflict{
		DoUpdates: clause.AssignmentColumns(columns),
	}).Create(v).Error
}
