package config

import (
	"fmt"
	"os"

	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/goccy/go-yaml"
)

var std *CoreConfig

// MainConfig 住配置
type MainConfig struct {
	App           string            `yaml:"app"`
	HttpAddr      string            `yaml:"http_addr"`
	GrpcAddr      string            `yaml:"grpc_addr"`
	OpenDocsAPI   bool              `yaml:"open_docs_api"`
	DatabaseConns map[string]string `yaml:"database_conns"`
	Env           string            `yaml:"env"`
}

// Config 。
type CoreConfig struct {
	MainConf MainConfig      `yaml:"main"`
	LogsConf logs.LogsConfig `yaml:"logger"`
}

// Conf .
func Conf() *CoreConfig {
	if std == nil {
		fmt.Println("config is nil")
		std = &CoreConfig{}
	}
	return std
}

// LoadCoreConfigFromFile .
func LoadCoreConfigFromFile(filepath string) (*CoreConfig, error) {
	cfg := &CoreConfig{}
	err := LoadYamlLocalFile(filepath, cfg)
	if err != nil {
		return nil, err
	}
	std = cfg
	return cfg, nil
}

// LoadCoreConfig 自动获取配置
func LoadCoreConfig(configPath ...string) (*CoreConfig, error) {
	if len(configPath) > 0 && configPath[0] != "" {
		return LoadCoreConfigFromFile(configPath[0])
	}
	// return LoadCoreConfigFromEnv()
	return nil, fmt.Errorf("no config file specified")
}

// LoadYamlLocalFile .
func LoadYamlLocalFile(file string, cfg interface{}) error {
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("[config] laod %s failed, %s\n", file, err)
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

// LoadCoreConfigFromEnv 通过环境变量获取远程配置
// YGCFG_AK
// YGCFG_SK
// YGCFG_GROUP
// YGCFG_KEY
func LoadCoreConfigFromEnv() (*CoreConfig, error) {
	// for _, envKey := range []string{"YGCFG_AK", "YGCFG_SK", "YGCFG_GROUP", "YGCFG_KEY"} {
	// 	if os.Getenv(envKey) == "" {
	// 		return nil, fmt.Errorf("%s is empty", envKey)
	// 	}
	// }
	// cfg := &CoreConfig{}
	// err := remote.GetRemoteYAML(os.Getenv("YGCFG_KEY"), cfg)
	// if err != nil {
	// 	return nil, err
	// }
	// std = cfg
	return nil, nil
}
