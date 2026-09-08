package dbtools

import (
	"fmt"
	"net/url"
	"sync"

	"github.com/JUXON-AI/jxpkg/logs"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var (
	dbs       = map[string]*gorm.DB{}
	dbsLocker sync.RWMutex
)

// InitDBConn 初始化数据库连接
func InitDBConn(name, dburl string) (*gorm.DB, error) {
	dsn, err := url.Parse(dburl)
	if err != nil {

		return nil, err
	}
	var db *gorm.DB
	switch dsn.Scheme {
	case "mysql":
		uri := ""
		uri, err = NormalizeMySQL(dsn)
		if err != nil {
			logs.Errorf("[init-db] normalize mysql dsn failed, %s", err)
			return nil, err
		}
		db, err = gorm.Open(mysql.Open(uri), &gorm.Config{
			CreateBatchSize: 200,
		})
	default:
		logs.Errorf("[init-db] unsupported db scheme %s", dsn.Scheme)
		return nil, fmt.Errorf("unsupported db scheme %s", dsn.Scheme)
	}
	if err != nil {
		logs.Errorf("[init-db] open db failed, %s", err)
		return nil, err
	}

	if name == "" {
		name = "default"
	}
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
