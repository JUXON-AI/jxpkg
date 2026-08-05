package config

import (
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// LogsConfig 日志配置集合，key 为日志器名称，value 为对应的 Writer 配置列表。
// 一个日志器可同时输出到多个 Writer（如同时写文件和控制台）。
type LogsConfig map[string][]LogConfig

// LogConfig 单个日志输出端的配置。
type LogConfig struct {
	Writer  string        `yaml:"writer"`  // 输出目标：console / file
	Encoder string        `yaml:"encoder"` // 编码格式：std / access
	Level   zapcore.Level `yaml:"level"`   // 日志级别
	*lumberjack.Logger    `yaml:",inline"` // 文件轮转配置（Writer 为 file 时生效）
}

// Get 返回指定名称的日志配置，不存在时返回默认配置。
func (c LogsConfig) Get(name string) []LogConfig {
	cfg, ok := c[name]
	if !ok {
		return []LogConfig{defaultLogConfig}
	}
	return cfg
}

// Default 返回默认日志配置，优先选择名为 "main" 或 "default" 的配置。
func (c LogsConfig) Default() []LogConfig {
	for _, name := range []string{"main", "default"} {
		cfg, ok := c[name]
		if !ok {
			break
		}
		return cfg
	}
	return []LogConfig{defaultLogConfig}
}

var defaultLogConfig = LogConfig{
	Writer: "console",
	Level:  zapcore.InfoLevel,
}