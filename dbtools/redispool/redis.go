package redispool

import (
	"context"
	"fmt"
	"sync"

	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/JUXON-AI/jxpkg/settings"
	"github.com/redis/go-redis/v9"
)

// RedisConfig redis 连接属性
type RedisConfig struct {
	Addr     string `yaml:"addr" json:"addr"`
	Password string `yaml:"password" json:"password"`
	DB       int    `yaml:"db" json:"db"`
}

var (
	redisMu      sync.RWMutex
	stdRedis     *redis.Client
	accountRedis *redis.Client
)

func loadRedis(group, key string) (*redis.Client, error) {
	cfg := &RedisConfig{}
	if err := settings.GetYaml(group, key, cfg); err != nil {
		logs.Errorf("[dbutil] load redis config failed, %s", err)
		return nil, err
	}

	return connectRedis(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
}

func connectRedis(cfg *redis.Options) (*redis.Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("redis config is nil")
	}

	rds := redis.NewClient(cfg)
	if err := rds.Ping(context.Background()).Err(); err != nil {
		_ = rds.Close()
		logs.Errorf("[dbutil] ping redis failed, %s", err)
		return nil, err
	}
	return rds, nil
}

// InitRedis 初始化redis连接
func InitRedis(group, key string) error {
	rds, err := loadRedis(group, key)
	if err != nil {
		return err
	}
	redisMu.Lock()
	stdRedis = rds
	redisMu.Unlock()

	InitCache(rds)
	return nil
}

// InitRedisWithConfig 初始化redis连接
func InitRedisWithConfig(cfg *redis.Options) (*redis.Client, error) {
	rds, err := connectRedis(cfg)
	if err != nil {
		return nil, err
	}
	redisMu.Lock()
	stdRedis = rds
	redisMu.Unlock()

	InitCache(rds)
	return rds, nil
}

// InitAccountRedis initializes the Redis connection owned by Account without
// replacing the default business Redis connection or CacheInstance.
func InitAccountRedis(group, key string) error {
	rds, err := loadRedis(group, key)
	if err != nil {
		return err
	}
	redisMu.Lock()
	accountRedis = rds
	redisMu.Unlock()
	return nil
}

// Redis 获取redis连接
func Redis() *redis.Client {
	redisMu.RLock()
	rds := stdRedis
	redisMu.RUnlock()
	if rds == nil {
		panic(fmt.Errorf("redis is nil"))
	}
	return rds
}

// GetRedis 获取redis连接, 可能为nil
func GetRedis() (*redis.Client, error) {
	redisMu.RLock()
	rds := stdRedis
	redisMu.RUnlock()
	if rds == nil {
		return nil, fmt.Errorf("redis is nil")
	}
	return rds, nil
}

// Account returns the Redis connection owned by Account.
func Account() *redis.Client {
	redisMu.RLock()
	rds := accountRedis
	redisMu.RUnlock()
	if rds == nil {
		panic(fmt.Errorf("account redis is nil"))
	}
	return rds
}

// GetAccountRedis returns the Redis connection owned by Account, or an error
// when Account Redis has not been initialized.
func GetAccountRedis() (*redis.Client, error) {
	redisMu.RLock()
	rds := accountRedis
	redisMu.RUnlock()
	if rds == nil {
		return nil, fmt.Errorf("account redis is nil")
	}
	return rds, nil
}
