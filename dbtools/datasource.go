package dbtools

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/JUXON-AI/jxpkg/logs"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	dbs       = map[string]*gorm.DB{}
	dbsLocker sync.RWMutex
)

const (
	defaultMaxOpenConns    = 25
	defaultMaxIdleConns    = 10
	defaultConnMaxLifetime = 5 * time.Minute
)

// InitDBConn 根据 URL 连接数据库并注册到全局连接池。
// 支持的 scheme: mysql、postgres/postgresql、sqlite/sqlite3。连接后自动配置连接池参数。
func InitDBConn(name, dburl string) (*gorm.DB, error) {
	dsn, err := url.Parse(dburl)
	if err != nil {
		logs.Errorf("[init-db] parse dburl(%s) failed, %s", dburl, err)
		return nil, err
	}
	var db *gorm.DB
	switch dsn.Scheme {
	case "mysql":
		uri, err := NormalizeMySQL(dsn)
		if err != nil {
			return nil, err
		}
		db, err = gorm.Open(mysql.Open(uri), &gorm.Config{CreateBatchSize: 200})
	case "postgres", "postgresql":
		uri, err := NormalizePostgres(dsn)
		if err != nil {
			return nil, err
		}
		db, err = gorm.Open(postgres.Open(uri), &gorm.Config{CreateBatchSize: 200})
	case "sqlite", "sqlite3":
		dbPath := strings.TrimPrefix(dsn.Path, "/")
		if dbPath == "" {
			dbPath = ":memory:"
		}
		db, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{CreateBatchSize: 200})
	default:
		return nil, fmt.Errorf("unsupported db scheme %s", dsn.Scheme)
	}
	if err != nil {
		logs.Errorf("[init-db] open %s(%s) failed, %s", dsn.Scheme, name, err)
		return nil, err
	}
	logs.Infof("[init-db] open %s(%s) success", dsn.Scheme, name)

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get underlying sql.DB failed: %s", err)
	}
	sqlDB.SetMaxOpenConns(defaultMaxOpenConns)
	sqlDB.SetMaxIdleConns(defaultMaxIdleConns)
	sqlDB.SetConnMaxLifetime(defaultConnMaxLifetime)

	if name == "" {
		name = "default"
	}
	dbsLocker.Lock()
	dbs[name] = db
	dbsLocker.Unlock()
	return db, nil
}

// InitMutilDBConn 批量初始化多个数据库连接并为每个连接设置 GORM 日志。
func InitMutilDBConn(dburls map[string]string) error {
	for name, dburl := range dburls {
		logs.Infof("[init-db] init db(%s) %s", name, dburl)
		db, err := InitDBConn(name, dburl)
		if err != nil {
			return err
		}
		db.Logger = logs.GetGorm("gorm")
	}
	return nil
}

// RegistryDB 将已有的 *gorm.DB 实例注册到连接池。重复注册会打印错误但不 panic。
func RegistryDB(name string, db *gorm.DB) {
	dbsLocker.Lock()
	defer dbsLocker.Unlock()
	if _, ok := dbs[name]; ok {
		logs.Errorf("[init-db] db %s is already exist", name)
		return
	}
	dbs[name] = db
	logs.Infof("[init-db] registry db %s success", name)
}

// DB 返回指定名称的数据库连接。不存在时会 panic。
func DB(name string) *gorm.DB {
	dbsLocker.RLock()
	db, ok := dbs[name]
	dbsLocker.RUnlock()
	if !ok {
		panic(fmt.Errorf("db %s is nil", name))
	}
	return db
}

// DBExists 检查指定名称的数据库连接是否已注册。
func DBExists(name string) bool {
	dbsLocker.RLock()
	defer dbsLocker.RUnlock()
	_, ok := dbs[name]
	return ok
}

// Std 返回名为 "default" 的默认数据库连接。
func Std() *gorm.DB { return DB("default") }

// Core 返回名为 "core" 的核心数据库连接。
func Core() *gorm.DB { return DB("core") }

// NormalizeMySQL 将 URL 格式的 MySQL 连接串转换为标准 DSN 格式。
func NormalizeMySQL(u *url.URL) (string, error) {
	user := u.User.Username()
	pass, _ := u.User.Password()
	pass, err := url.QueryUnescape(pass)
	if err != nil {
		return "", fmt.Errorf("decode password failed: %s", err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "3306"
	}
	db := strings.TrimPrefix(u.Path, "/")
	query := u.RawQuery
	if query != "" {
		query = "?" + query
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s%s", user, pass, host, port, db, query), nil
}

// NormalizePostgres 将 URL 格式的 PostgreSQL 连接串转换为 key=value DSN 格式。
// 输入: postgres://user:pass@host:5432/dbname?sslmode=disable
// 输出: host=host port=5432 user=user password=pass dbname=dbname sslmode=disable
func NormalizePostgres(u *url.URL) (string, error) {
	user := u.User.Username()
	pass, _ := u.User.Password()
	pass, err := url.QueryUnescape(pass)
	if err != nil {
		return "", fmt.Errorf("decode password failed: %s", err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	db := strings.TrimPrefix(u.Path, "/")

	params := []string{
		fmt.Sprintf("host=%s", host),
		fmt.Sprintf("port=%s", port),
		fmt.Sprintf("user=%s", user),
		fmt.Sprintf("password=%s", pass),
		fmt.Sprintf("dbname=%s", db),
	}
	for k, v := range u.Query() {
		if len(v) > 0 {
			params = append(params, fmt.Sprintf("%s=%s", k, v[0]))
		}
	}
	return strings.Join(params, " "), nil
}
