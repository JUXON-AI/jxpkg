package dbtools

import (
	"context"
	"fmt"

	"github.com/JUXON-AI/jxpkg/config"
	"github.com/redis/go-redis/v9"
)

var stdRedis *redis.Client

// InitRedisWithConfig 使用 RedisConfig 初始化 Redis 客户端并设为全局实例。
func InitRedisWithConfig(cfg *config.RedisConfig) (*redis.Client, error) {
	rds := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	err := rds.Ping(context.Background()).Err()
	if err != nil {
		return nil, fmt.Errorf("ping redis failed: %s", err)
	}
	stdRedis = rds
	return rds, nil
}

// InitRedis 使用地址、密码、数据库编号初始化 Redis 客户端。
func InitRedis(addr, password string, db int) (*redis.Client, error) {
	return InitRedisWithConfig(&config.RedisConfig{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
}

// Redis 返回全局 Redis 客户端实例，未初始化时会 panic。
func Redis() *redis.Client {
	if stdRedis == nil {
		panic("redis is nil, please call InitRedis first")
	}
	return stdRedis
}
