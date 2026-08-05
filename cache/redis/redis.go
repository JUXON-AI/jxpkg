package redis

import (
	"context"
	"time"

	"github.com/JUXON-AI/jxpkg/cache"
	goredis "github.com/redis/go-redis/v9"
)

// Redis 基于 go-redis 的缓存实现。
type Redis struct {
	ctx  context.Context
	conn *goredis.Client
}

// NewCache 创建使用指定 Redis 客户端的缓存实例。
func NewCache(rds *goredis.Client) *Redis {
	return &Redis{conn: rds, ctx: context.Background()}
}

// Get 从 Redis 读取 key 对应的值并反序列化到 val 中。
func (r *Redis) Get(key string, val interface{}) error {
	data, err := r.conn.Get(r.ctx, key).Result()
	if err != nil {
		return err
	}
	return cache.Unmarshal([]byte(data), val)
}

// Set 将 key-value 存入 Redis，timeout 为过期时长（0 表示永不过期）。
func (r *Redis) Set(key string, val interface{}, timeout time.Duration) error {
	data, err := cache.Marshal(val)
	if err != nil {
		return err
	}
	_, err = r.conn.Set(r.ctx, key, data, timeout).Result()
	return err
}

// IsExist 判断 key 在 Redis 中是否存在。
func (r *Redis) IsExist(key string) bool {
	n, err := r.conn.Exists(r.ctx, key).Result()
	return err == nil && n > 0
}

// Delete 删除 Redis 中的指定 key。
func (r *Redis) Delete(key string) error {
	_, err := r.conn.Del(r.ctx, key).Result()
	return err
}
