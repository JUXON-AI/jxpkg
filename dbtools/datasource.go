package dbtools

import (
	"fmt"
	"net/url"
	"os"
	"sync"

	"github.com/JUXON-AI/jxpkg/logs"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	dbs       = map[string]*gorm.DB{}
	dbsLocker sync.RWMutex
)

// InitDBConn 初始化数据库连接
func InitDBConn(name, dburl string) (*gorm.DB, error) {
	pool, err := databasePoolOptions(name, os.Getenv)
	if err != nil {
		return nil, err
	}
	dsn, err := url.Parse(dburl)
	if err != nil {
		return nil, fmt.Errorf("parse database connection URL failed")
	}
	var db *gorm.DB
	switch dsn.Scheme {
	case "mysql":
		uri := ""
		uri, err = NormalizeMySQL(dsn)
		if err != nil {
			logs.Error("[init-db] normalize mysql dsn failed")
			return nil, fmt.Errorf("normalize MySQL connection failed")
		}
		db, err = gorm.Open(mysql.Open(uri), &gorm.Config{
			CreateBatchSize: 200,
			// 初始化错误可能包含凭证或原始驱动参数，仅由本层输出固定事件。
			Logger: logger.Default.LogMode(logger.Silent),
		})
	default:
		logs.Error("[init-db] unsupported db scheme")
		return nil, fmt.Errorf("unsupported database connection scheme")
	}
	if err != nil {
		logs.Error("[init-db] open db failed")
		return nil, fmt.Errorf("open database connection failed")
	}

	if name == "" {
		name = "default"
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get database pool %s: %w", name, err)
	}
	pool.apply(sqlDB)
	db.Logger = logs.GetGorm("gorm")
	logs.Infow("dbtools.InitDBConn pool configured", "database", name,
		"max_open_conns", pool.maxOpen, "max_idle_conns", pool.maxIdle,
		"conn_max_idle_time", pool.idleTime.String(), "conn_max_lifetime", pool.lifetime.String())
	dbsLocker.Lock()
	dbs[name] = db
	dbsLocker.Unlock()

	return db, nil
}

// InitMutilDBConn 批量初始化数据库
func InitMutilDBConn(dburls map[string]string) error {
	for name, dburl := range dburls {
		// Database URLs can contain credentials and driver options. Log only the
		// protocol, address and database name so startup diagnostics never expose
		// the username, password, query string or fragment.
		logs.Infof("[init-db] init db(%s) %s", name, redactedDatabaseURL(dburl))
		db, err := InitDBConn(name, dburl)
		if err != nil {
			return err
		}
		db.Logger = logs.GetGorm("gorm")
	}
	return nil
}

func redactedDatabaseURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "<invalid-database-url>"
	}

	return (&url.URL{
		Scheme: parsed.Scheme,
		Host:   parsed.Host,
		Path:   parsed.Path,
	}).String()
}

// DB 获取数据库连接
func DB(name string) *gorm.DB {
	dbsLocker.RLock()
	db, ok := dbs[name]
	dbsLocker.RUnlock()
	if !ok {
		panic(fmt.Errorf("db %s is nil", name))
	}
	return db
}

// DBExists 判断数据库是否存在
func DBExists(name string) bool {
	dbsLocker.RLock()
	defer dbsLocker.RUnlock()
	_, ok := dbs[name]
	return ok
}
