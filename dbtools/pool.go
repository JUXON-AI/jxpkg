package dbtools

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// poolOptions 保留标准库默认值，只对显式配置的命名数据库调整连接复用。
type poolOptions struct {
	maxOpen  int
	maxIdle  int
	idleTime time.Duration
	lifetime time.Duration
}

func databasePoolOptions(name string, getenv func(string) string) (poolOptions, error) {
	if name == "" {
		name = "default"
	}
	prefix := "JX_DB_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_"
	options := poolOptions{maxIdle: 2}
	for _, item := range []struct {
		key    string
		target *int
	}{
		{"MAX_OPEN_CONNS", &options.maxOpen},
		{"MAX_IDLE_CONNS", &options.maxIdle},
	} {
		raw := getenv(prefix + item.key)
		if raw == "" {
			continue
		}
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 {
			return poolOptions{}, fmt.Errorf("invalid database pool option %s", prefix+item.key)
		}
		*item.target = value
	}
	for _, item := range []struct {
		key    string
		target *time.Duration
	}{
		{"CONN_MAX_IDLE_TIME", &options.idleTime},
		{"CONN_MAX_LIFETIME", &options.lifetime},
	} {
		raw := getenv(prefix + item.key)
		if raw == "" {
			continue
		}
		value, err := time.ParseDuration(raw)
		if err != nil || value < 0 {
			return poolOptions{}, fmt.Errorf("invalid database pool option %s", prefix+item.key)
		}
		*item.target = value
	}
	if options.maxOpen > 0 && options.maxIdle > options.maxOpen {
		return poolOptions{}, fmt.Errorf("database pool %s: max idle exceeds max open", name)
	}
	return options, nil
}

func (options poolOptions) apply(db *sql.DB) {
	db.SetMaxOpenConns(options.maxOpen)
	db.SetMaxIdleConns(options.maxIdle)
	db.SetConnMaxIdleTime(options.idleTime)
	db.SetConnMaxLifetime(options.lifetime)
}
