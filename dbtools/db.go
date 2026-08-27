package dbtools

import (
	"gorm.io/gorm"
)

// Account 返回 account 数据库连接。
func Account() *gorm.DB {
	return DB("account")
}

// Core 返回 core 数据库连接。
func Core() *gorm.DB {
	return DB("core")
}

// Jxone 返回 jxone 数据库连接。
func Jxone() *gorm.DB {
	return DB("jxone")
}
