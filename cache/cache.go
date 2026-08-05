package cache

import (
	"encoding/json"
	"time"

	"github.com/JUXON-AI/jxpkg/cache/memory"
)

// Cache 通用缓存接口，支持 Set/Get/Delete/IsExist 操作。
// 可接入内存缓存或 Redis 等后端实现。
type Cache interface {
	Get(key string, val interface{}) error
	Set(key string, val interface{}, timeout time.Duration) error
	IsExist(key string) bool
	Delete(key string) error
}

var std Cache

// InitCache 设置全局缓存实例。应在应用启动时调用。
func InitCache(c Cache) {
	std = c
}

// Std 返回全局缓存实例，未初始化时默认使用内存缓存。
func Std() Cache {
	if std == nil {
		std = memory.NewCache()
	}
	return std
}

// Marshal 将 v 序列化为 JSON 字节切片。
func Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// Unmarshal 将 JSON 数据反序列化到 v 中。
func Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
