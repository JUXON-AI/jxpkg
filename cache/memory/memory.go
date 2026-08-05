package memory

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type data struct {
	bytes   []byte
	expired time.Time
}

// Memory 基于 sync.RWMutex + map 的进程内缓存实现。
type Memory struct {
	sync.RWMutex
	items map[string]*data
}

// NewCache 创建内存缓存实例。
func NewCache() *Memory {
	return &Memory{items: make(map[string]*data)}
}

// Get 读取 key 对应的值并反序列化到 val 中。
func (m *Memory) Get(key string, val interface{}) error {
	m.RLock()
	d, ok := m.items[key]
	m.RUnlock()
	if !ok {
		return fmt.Errorf("key %s not found", key)
	}
	if !d.expired.IsZero() && time.Now().After(d.expired) {
		m.Delete(key)
		return fmt.Errorf("key %s expired", key)
	}
	return json.Unmarshal(d.bytes, val)
}

// Set 存储 key-value，timeout 为 0 表示永不过期。
func (m *Memory) Set(key string, val interface{}, timeout time.Duration) error {
	raw, err := json.Marshal(val)
	if err != nil {
		return err
	}
	d := &data{bytes: raw}
	if timeout > 0 {
		d.expired = time.Now().Add(timeout)
	}
	m.Lock()
	m.items[key] = d
	m.Unlock()
	return nil
}

// IsExist 判断 key 是否存在且未过期。
func (m *Memory) IsExist(key string) bool {
	m.RLock()
	defer m.RUnlock()
	d, ok := m.items[key]
	if !ok {
		return false
	}
	if !d.expired.IsZero() && time.Now().After(d.expired) {
		return false
	}
	return true
}

// Delete 删除指定 key。
func (m *Memory) Delete(key string) error {
	m.Lock()
	delete(m.items, key)
	m.Unlock()
	return nil
}
