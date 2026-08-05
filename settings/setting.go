package settings

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/JUXON-AI/jxpkg/cache"
	"github.com/JUXON-AI/jxpkg/dbtools"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// TableNameSettings Settings 表名。
const TableNameSettings = "core_settings"

const (
	ValueText     = "text"
	ValueInt64    = "int64"
	ValueBool     = "bool"
	ValueJSON     = "json"
	ValueYaml     = "yaml"
	ValueSecret   = "secret"
	ValuePassword = "password"
)

// SettingGroupCore 核心配置组。
const SettingGroupCore = "core"

const settingsCacheTTL = 5 * time.Minute

// SettingItem 配置项模型。
type SettingItem struct {
	gorm.Model
	Group     string `gorm:"column:group;type:varchar(16);uniqueIndex:idx_setting,priority:2,unique"`
	Key       string `gorm:"column:key;type:varchar(64);uniqueIndex:idx_setting,priority:3,unique"`
	Name      string `gorm:"column:name;type:varchar(64)"`
	Describe  string `gorm:"column:describe;type:varchar(128)"`
	ValueType string `gorm:"column:value_type;default:text;type:varchar(16)"`
	Value     string `gorm:"column:value;type:text"`
	Default   string `gorm:"column:default;type:text"`
}

func (SettingItem) TableName() string { return TableNameSettings }

// BeforeSave GORM Hook：secret/password 类型写入前自动加密。
func (item *SettingItem) BeforeSave(tx *gorm.DB) error {
	if item.ValueType == ValueSecret || item.ValueType == ValuePassword {
		item.Value = EncryptSecret(item.Value)
	}
	return nil
}

// SecretValue 返回解密后的值（仅对 secret/password 类型生效）。
func (item *SettingItem) SecretValue() string {
	if item.ValueType == ValueSecret || item.ValueType == ValuePassword {
		return DecryptSecret(item.Value)
	}
	return item.Value
}

// InitDB 初始化 core 数据库的 settings 表。
func InitDB() error {
	return dbtools.InitModel(dbtools.Core(), &SettingItem{})
}

func redisCacheKey(group, key string) string {
	return fmt.Sprintf("core_setting::%s::%s", group, key)
}

// Get 查询指定 group 和 key 的配置项，优先读取 Redis 缓存。
func Get(group, key string) (*SettingItem, error) {
	ret := &SettingItem{}
	rdsKey := redisCacheKey(group, key)
	if err := cache.Std().Get(rdsKey, ret); err == nil && ret.Key != "" {
		return ret, nil
	}
	err := dbtools.Core().Table(TableNameSettings).
		Where("`group` = ? AND `key` = ?", group, key).
		First(ret).Error
	if err != nil {
		return nil, err
	}
	cache.Std().Set(rdsKey, ret, settingsCacheTTL)
	return ret, nil
}

// GetValue 查询配置项并以解密后的字符串形式返回。
func GetValue(group, key string) (string, error) {
	item, err := Get(group, key)
	if err != nil {
		return "", err
	}
	return item.SecretValue(), nil
}

// GetText 查询文本类型的配置值，等同于 GetValue。
func GetText(group, key string) (string, error) {
	return GetValue(group, key)
}

// GetSecret 查询 secret/password 配置项并返回解密后的值。
func GetSecret(group, key string) (string, error) {
	item, err := Get(group, key)
	if err != nil {
		return "", err
	}
	return DecryptSecret(item.Value), nil
}

// GetYaml 查询 YAML 类型的配置值并反序列化到 value 中。
func GetYaml(group, key string, value interface{}) error {
	v, err := GetValue(group, key)
	if err != nil {
		return err
	}
	return yaml.Unmarshal([]byte(v), value)
}

// GetSecretYaml 查询加密的 YAML 配置值并反序列化到 value 中。
func GetSecretYaml(group, key string, value interface{}) error {
	v, err := GetSecret(group, key)
	if err != nil {
		return err
	}
	return yaml.Unmarshal([]byte(v), value)
}

// GetJSON 查询 JSON 类型的配置值并反序列化到 value 中。
func GetJSON(group, key string, value interface{}) error {
	v, err := GetValue(group, key)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(v), value)
}

// Set 设置文本类型的配置值，等价于 SetText。
func Set(group, key, value string) error {
	return SetText(group, key, value)
}

// SetText 设置文本类型的配置项。
func SetText(group, key, value string) error {
	return UpsertSetting(&SettingItem{
		Group:     group,
		Key:       key,
		Value:     value,
		ValueType: ValueText,
	})
}

// SetYaml 将 value 序列化为 YAML 后写入配置。
func SetYaml(group, key string, value interface{}) error {
	data, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	return UpsertSetting(&SettingItem{
		Group:     group,
		Key:       key,
		Value:     string(data),
		ValueType: ValueYaml,
	})
}

// UpsertSetting 插入或更新配置项（基于 group+key 联合唯一索引）。
// 写入前会清除对应的 Redis 缓存。
func UpsertSetting(v *SettingItem) error {
	rdsKey := redisCacheKey(v.Group, v.Key)
	cache.Std().Delete(rdsKey)
	return dbtools.Core().Table(TableNameSettings).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "group"}, {Name: "key"}},
			DoUpdates: clause.AssignmentColumns([]string{"value", "value_type", "name", "describe", "default", "updated_at"}),
		}).Create(v).Error
}

// Updates 批量更新配置项。有 ID 则 Save，无 ID 则按 group+key 匹配更新或创建。
func Updates(sets ...*SettingItem) error {
	for _, v := range sets {
		rdsKey := redisCacheKey(v.Group, v.Key)
		cache.Std().Delete(rdsKey)
		if v.ID > 0 {
			if err := dbtools.Core().Table(TableNameSettings).Save(v).Error; err != nil {
				return err
			}
		} else {
			if err := dbtools.Core().Table(TableNameSettings).
				Where("`group` = ? AND `key` = ?", v.Group, v.Key).
				Assign(map[string]interface{}{"value": v.Value, "value_type": v.ValueType, "name": v.Name, "describe": v.Describe}).
				FirstOrCreate(v).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

// List 查询指定 group 下的配置项列表，可通过 keys 筛选。
func List(group string, keys ...string) ([]*SettingItem, error) {
	var items []*SettingItem
	query := dbtools.Core().Table(TableNameSettings).Where("`group` = ?", group)
	if len(keys) > 0 {
		query = query.Where("`key` IN ?", keys)
	}
	if err := query.Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

// GetByID 根据主键 ID 查询配置项。
func GetByID(id uint) (*SettingItem, error) {
	item := &SettingItem{}
	if err := dbtools.Core().Table(TableNameSettings).First(item, id).Error; err != nil {
		return nil, err
	}
	return item, nil
}
