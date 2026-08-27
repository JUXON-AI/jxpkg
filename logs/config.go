package logs

import (
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	WriterConsole = "console"
	WriterStdout  = "stdout"
	WriterStderr  = "stderr"
	WriterFile    = "file"

	EncoderStandard = "std"
	EncoderAccess   = "access"
	EncoderConsole  = "console"
)

// LogsConfig 保存各命名日志器的输出配置。
type LogsConfig map[string][]LogConfig

// LogConfig 定义单个日志输出；同一命名日志器可以配置多个输出。
type LogConfig struct {
	Writer             string        `json:"writer" yaml:"writer"`
	Encoder            string        `json:"encoder" yaml:"encoder"`
	Level              zapcore.Level `json:"level" yaml:"level"`
	*lumberjack.Logger `json:"file,omitempty" yaml:",inline"`
}

var defaultLogConfig = LogConfig{
	Writer: WriterConsole,
	Level:  zapcore.InfoLevel,
}

// Get 获取指定名称的日志配置，不存在时返回默认输出配置。
func (c LogsConfig) Get(name string) []LogConfig {
	if cfg, ok := c[name]; ok {
		return cfg
	}
	return []LogConfig{defaultLogConfig}
}

// Default 获取默认日志配置，优先使用 default，并兼容旧配置中的 main。
func (c LogsConfig) Default() []LogConfig {
	if cfg, ok := c["default"]; ok {
		return cfg
	}
	if cfg, ok := c["main"]; ok {
		return cfg
	}
	return []LogConfig{defaultLogConfig}
}
