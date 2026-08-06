package dbtools

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/JUXON-AI/jxpkg/config"
	"github.com/redis/go-redis/v9"
)

var (
	stdRedis   *redis.Client
	redisMutex sync.RWMutex
)

// InitRedisWithConfig 使用 RedisConfig 初始化 Redis 客户端并设为全局实例。
func InitRedisWithConfig(cfg *config.RedisConfig) (*redis.Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("redis config is nil")
	}
	rds := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := rds.Ping(ctx).Err()
	if err != nil {
		_ = rds.Close()
		return nil, fmt.Errorf("ping redis failed: %s", err)
	}
	redisMutex.Lock()
	previous := stdRedis
	stdRedis = rds
	redisMutex.Unlock()
	if previous != nil {
		_ = previous.Close()
	}
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
	redisMutex.RLock()
	defer redisMutex.RUnlock()
	if stdRedis == nil {
		panic("redis is nil, please call InitRedis first")
	}
	return stdRedis
}

// CloseRedis closes and clears the global Redis client.
func CloseRedis() error {
	redisMutex.Lock()
	rds := stdRedis
	stdRedis = nil
	redisMutex.Unlock()
	if rds == nil {
		return nil
	}
	return rds.Close()
}
