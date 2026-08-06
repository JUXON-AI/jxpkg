package config

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	std *CoreConfig
	mu  sync.RWMutex
)

const minJWTSecretLength = 32

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
	CORS          CORSConfig        `yaml:"cors"`
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
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
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
		return fmt.Errorf("open config file: %w", err)
	}
	defer f.Close()
	return decodeYAML(f, cfg)
}

// LoadYamlReader 从 io.Reader 读取 YAML 并解码到 cfg 中。
func LoadYamlReader(r io.Reader, cfg interface{}) error {
	if r == nil {
		return fmt.Errorf("yaml reader is nil")
	}
	return decodeYAML(r, cfg)
}

func decodeYAML(r io.Reader, cfg interface{}) error {
	if cfg == nil {
		return fmt.Errorf("yaml destination is nil")
	}
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		return fmt.Errorf("decode yaml: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode yaml: multiple documents are not allowed")
		}
		return fmt.Errorf("decode yaml: %w", err)
	}
	return nil
}

// Validate checks the configuration required by the application runtime.
func (c *CoreConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}
	if strings.TrimSpace(c.MainConf.App) == "" {
		return fmt.Errorf("main.app is required")
	}
	if strings.TrimSpace(c.MainConf.Env) == "" {
		return fmt.Errorf("main.env is required")
	}
	if _, _, err := net.SplitHostPort(strings.TrimSpace(c.MainConf.HttpAddr)); err != nil {
		return fmt.Errorf("main.http_addr is invalid: %w", err)
	}
	coreDSN := strings.TrimSpace(c.MainConf.DatabaseConns["core"])
	if coreDSN == "" {
		return fmt.Errorf("main.database_conns.core is required")
	}
	parsedDSN, err := url.Parse(coreDSN)
	if err != nil || parsedDSN.Scheme == "" {
		return fmt.Errorf("main.database_conns.core is invalid")
	}
	if len(c.MainConf.JWT.Secret) < minJWTSecretLength {
		return fmt.Errorf("main.jwt.secret must contain at least %d bytes", minJWTSecretLength)
	}
	if c.MainConf.JWT.Expire <= 0 {
		return fmt.Errorf("main.jwt.expire must be positive")
	}
	if c.MainConf.Redis.DB < 0 {
		return fmt.Errorf("main.redis.db cannot be negative")
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
func IsDev() bool { return Env() == "dev" }

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
	Prefix   string `yaml:"prefix" json:"prefix"`
}

// CORSConfig contains the exact browser origins allowed to call the API.
type CORSConfig struct {
	AllowedOrigins []string `yaml:"allowed_origins" json:"allowed_origins"`
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
