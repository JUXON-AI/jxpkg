package dbtools

import (
	"github.com/JUXON-AI/jxpkg/logs"
	"gorm.io/gorm"
)

type InitModelFunc func() error

// InitModel 工具类，自动生成表结构，gorm中的AutoMIGRATE
func InitModel(db *gorm.DB, models ...interface{}) error {
	for _, v := range models {
		if err := db.AutoMigrate(v); err != nil {
			logs.Errorf("[init-db] auto migrate %T failed, %s", v, err)
			return err
		}
	}
	return nil
}

// DoInitModels 使用默认db初始化模型
func DoInitModels(imfs ...InitModelFunc) error {
	for _, imf := range imfs {
		if err := imf(); err != nil {
			logs.Errorf("[init-db] do %T failed, %s", imf, err)
			return err
		}
	}
	return nil
}
