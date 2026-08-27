package settings

import (
	"encoding/json"

	"github.com/JUXON-AI/jxpkg/dbtools"
	"go.yaml.in/yaml/v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	TableNameSettings = "core_settings"
)

type ValueType string

const (
	// ValueSecret   ValueType = "secret"
	// ValuePassword ValueType = "password"
	ValueText  ValueType = "text"
	ValueInt64 ValueType = "int64"
	ValueBool  ValueType = "bool"
	ValueJSON  ValueType = "json"
	ValueYaml  ValueType = "yaml"
)

// SettingItem 系统配置
type SettingItem struct {
	gorm.Model

	Group     string    `json:"group" yaml:"group" gorm:"column:group;type:varchar(16);uniqueIndex:idx_setting,priority:2,unique"`
	Key       string    `json:"key" yaml:"key" gorm:"column:key;type:varchar(64);uniqueIndex:idx_setting,priority:3,unique"`
	Name      string    `json:"name" yaml:"name" gorm:"column:name;type:varchar(64)"`
	Describe  string    `json:"describe" yaml:"describe" gorm:"column:describe;type:varchar(128)"`
	ValueType ValueType `json:"value_type" yaml:"value_type" gorm:"column:value_type;default:text;type:varchar(16)"`
	Value     string    `json:"value" yaml:"value" gorm:"column:value;type:text"`
	Default   string    `json:"default" yaml:"default" gorm:"column:default;type:text"`
}

// TableName .
func (*SettingItem) TableName() string {
	return TableNameSettings
}

// InitDB .
func InitDB() error {
	return dbtools.InitModel(
		dbtools.Core(),
		&SettingItem{},
	)
}

// GetByID .
func GetByID(id uint) (*SettingItem, error) {
	ret := &SettingItem{}
	err := dbtools.Core().Table(TableNameSettings).
		Where("id = ?", id).
		Find(ret).Error
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// Set .
func Set(group, key, value string) error {
	return SetText(group, key, value)
}

func SetText(group, key, value string) error {
	si := &SettingItem{
		Group:     group,
		Key:       key,
		Value:     value,
		ValueType: ValueText,
	}
	return UpsertSetting(si)
}

// SetYaml 插入yaml配置
func SetYaml(group, key string, value interface{}) error {
	vData, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	si := &SettingItem{
		Group:     group,
		Key:       key,
		Value:     string(vData),
		ValueType: ValueYaml,
	}
	return UpsertSetting(si)
}

// UpsertSetting or update the trade calendar of a stock.
func UpsertSetting(v *SettingItem) error {
	// rdsKey := redisCacheKey(v.Group, v.Key)
	// cache.Std().Delete(rdsKey)
	return dbtools.Core().Table(TableNameSettings).
		Clauses(clause.OnConflict{
			DoUpdates: clause.AssignmentColumns([]string{"name", "describe", "value", "value_type", "default"}),
		}).Create(v).Error
}

// Get 获取数据库或者缓存配置项
func Get(group, key string) (*SettingItem, error) {
	ret := &SettingItem{}

	err := dbtools.Core().Table(TableNameSettings).
		Where("`group` = ? AND `key` = ?", group, key).
		First(ret).Error
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// GetValue 获取配置值，如果是加密配置，返回解密后的值
func GetValue(group, key string) (string, error) {
	si, err := Get(group, key)
	if err != nil {
		return "", err
	}
	return si.Value, nil
}

// GetYaml 获取yaml配置
func GetYaml(group, key string, value interface{}) error {
	text, err := GetValue(group, key)
	if err != nil {
		return err
	}
	return yaml.Unmarshal([]byte(text), value)
}

// GetText 获取文本配置
func GetText(group, key string) (string, error) {
	return GetValue(group, key)
}

// GetJSON 获取json配置
func GetJSON(group, key string, value interface{}) error {
	text, err := GetValue(group, key)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(text), value)
}
