package config

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	std  *CoreConfig
	mu   sync.RWMutex
)

// CoreConfig 顶层配置结构，包含 main 和 logger 两个模块。
type CoreConfig struct {
	MainConf MainConfig `yaml:"main"`
	LogsConf LogsConfig `yaml:"logger"`
}

// Conf 返回全局配置实例。未加载时返回空配置（不 panic）。
func Conf() *CoreConfig {
	mu.RLock()
	c := std
	mu.RUnlock()
	if c == nil {
		fmt.Println("config is nil")
		return &CoreConfig{}
	}
	return c
}

// MainConfig 应用主配置。
type MainConfig struct {
	App           string            `yaml:"app"`
	HttpAddr      string            `yaml:"http_addr"`
	DatabaseConns map[string]string `yaml:"database_conns"`
	Redis         RedisConfig       `yaml:"redis"`
	JWT           JwtConfig         `yaml:"jwt"`
	Env           string            `yaml:"env"`
}

// LoadCoreConfigFromFile 从 YAML 文件加载配置并设为全局配置。
func LoadCoreConfigFromFile(filepath string) (*CoreConfig, error) {
	cfg := &CoreConfig{}
	err := LoadYamlLocalFile(filepath, cfg)
	if err != nil {
		return nil, err
	}
	mu.Lock()
	std = cfg
	mu.Unlock()
	return cfg, nil
}

// LoadCoreConfig 加载配置。configPath 为空时返回错误。
func LoadCoreConfig(configPath ...string) (*CoreConfig, error) {
	if len(configPath) > 0 && configPath[0] != "" {
		return LoadCoreConfigFromFile(configPath[0])
	}
	return nil, fmt.Errorf("config path is empty")
}

// LoadYamlLocalFile 从本地文件路径加载 YAML 到 cfg 中。
func LoadYamlLocalFile(file string, cfg interface{}) error {
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("[config] load %s failed, %s\n", file, err)
		return err
	}
	defer f.Close()
	err = yaml.NewDecoder(f).Decode(cfg)
	if err != nil {
		fmt.Printf("[config] decode %s failed, %s\n", file, err)
		return err
	}
	return nil
}

// LoadYamlReader 从 io.Reader 读取 YAML 并解码到 cfg 中。
func LoadYamlReader(r io.Reader, cfg interface{}) error {
	err := yaml.NewDecoder(r).Decode(cfg)
	if err != nil {
		fmt.Printf("[config] decode %T failed, %s\n", r, err)
		return err
	}
	return nil
}

// Env 返回当前环境，优先取配置中的 env，其次取环境变量 ENV。
func Env() string {
	if cfgEnv := Conf().MainConf.Env; cfgEnv != "" {
		return cfgEnv
	}
	if env := os.Getenv("ENV"); env != "" {
		return env
	}
	return ""
}

// IsProd 判断当前是否为生产环境。
func IsProd() bool { return Env() == "prod" }

// IsDev 判断当前是否为开发环境。
func IsDev() bool  { return Env() == "dev" }

// JwtConfig JWT 认证配置。
type JwtConfig struct {
	Secret string        `yaml:"secret"`
	Expire time.Duration `yaml:"expire"`
}

// MysqlConfig MySQL 连接配置。
type MysqlConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
	Charset  string `yaml:"charset"`
}

// BuildDNS 根据配置生成 MySQL DSN 连接字符串。
func (cfg *MysqlConfig) BuildDNS() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=true&loc=Local",
		cfg.Username, cfg.Password, cfg.Host, cfg.Port, cfg.Database, cfg.Charset)
}

// RedisConfig Redis 连接配置。
type RedisConfig struct {
	Addr     string `yaml:"addr" json:"addr"`
	Password string `yaml:"password" json:"password"`
	DB       int    `yaml:"db" json:"db"`
}

// PgConfig PostgreSQL 连接配置。
type PgConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
	SSLMode  string `yaml:"sslmode"`
}

// BuildDSN 根据配置生成 PostgreSQL DSN（key=value 格式）。
func (cfg *PgConfig) BuildDSN() string {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s",
		cfg.Host, cfg.Port, cfg.Username, cfg.Password, cfg.Database)
	if cfg.SSLMode != "" {
		dsn += " sslmode=" + cfg.SSLMode
	}
	return dsn
}