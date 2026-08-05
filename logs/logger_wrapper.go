package logs

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/JUXON-AI/jxpkg/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type loggerWrapper struct {
	module, name string
	core         zapcore.Core
	logger       *zap.SugaredLogger
}

var (
	closerList  []io.Closer = []io.Closer{}
	loggers                 = map[string]*loggerWrapper{"default": {name: "default"}}
	loggersLock             = new(sync.RWMutex)

	stdcfg = zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "lvl",
		NameKey:        "mod",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	accessCfg = zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "lvl",
		NameKey:        "reqid",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.TimeEncoderOfLayout("01-02T15:04:05.000"),
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
)

func init() {
	loggersLock.Lock()
	lg := loggers["default"]
	lg.load("-", []config.LogConfig{})
	logger = lg.logger
	loggersLock.Unlock()
}

// Get 获取指定名称的 SugaredLogger。不存在时返回以该名称命名的默认 logger。
func Get(lgr string) *zap.SugaredLogger {
	loggersLock.RLock()
	defer loggersLock.RUnlock()
	lw := loggers[lgr]
	if lw == nil {
		if lgr != "" && lgr != "default" {
			return logger.Named(lgr)
		}
		return logger
	}
	return lw.logger
}

// ReloadConfig 重新加载日志配置。会更新所有日志器并替换全局默认 logger。
func ReloadConfig(module string, cfg config.LogsConfig) error {
	loggersLock.Lock()
	defer loggersLock.Unlock()
	for name, cfgs := range cfg {
		if lw, ok := loggers[name]; !ok {
			loggers[name] = newLoggerWrapper(module, name, cfgs)
		} else {
			lw.load(module, cfgs)
		}
	}
	logger = loggers["default"].logger
	return nil
}

// Desugar 返回底层 *zap.Logger。
func Desugar() *zap.Logger { return logger.Desugar() }

// Named 返回以 name 命名的子 logger。
func Named(name string) *zap.SugaredLogger { return logger.Named(name) }

// RequestLogger 返回 access 日志器中以 reqid 命名的 logger。
func RequestLogger(reqid string) *zap.SugaredLogger {
	return Get("access").Named(reqid)
}

func newLoggerWrapper(module, name string, cfgs []config.LogConfig) *loggerWrapper {
	lw := &loggerWrapper{module: module, name: name}
	lw.load(module, cfgs)
	return lw
}

func (lw *loggerWrapper) load(module string, cfgs []config.LogConfig) {
	lw.module = module
	if len(cfgs) == 0 {
		cfgs = []config.LogConfig{{}}
	}
	cores := make([]zapcore.Core, 0, len(cfgs))
	for _, lcfg := range cfgs {
		edr := getLoggerEncoder(lcfg.Encoder)
		lvl := zap.NewAtomicLevelAt(lcfg.Level)
		var syncer zapcore.WriteSyncer
		switch lcfg.Writer {
		case "file":
			syncer = zapcore.AddSync(lcfg.Logger)
		case "console", "stdout", "":
			syncer = zapcore.Lock(os.Stdout)
		default:
			panic(fmt.Errorf("unsupport logger writer (%s)", lcfg.Writer))
		}
		core := zapcore.NewCore(edr, syncer, lvl)
		cores = append(cores, core)
	}

	opts := []zap.Option{zap.AddCaller(), zap.AddCallerSkip(1)}
	fields := []zap.Field{}
	if module != "-" && lw.name != "" {
		fields = append(fields, zap.String("module", module))
	}
	if lw.name != "default" {
		fields = append(fields, zap.String("logger", lw.name))
	}
	opts = append(opts, zap.Fields(fields...))
	lw.core = zapcore.NewTee(cores...)
	lw.logger = zap.New(lw.core, opts...).Sugar()
}

func getLoggerEncoder(edr string) zapcore.Encoder {
	switch edr {
	case "access":
		return zapcore.NewJSONEncoder(accessCfg)
	case "", "std", "default":
	default:
		panic(fmt.Errorf("unsupport logger encoder (%s)", edr))
	}
	return zapcore.NewJSONEncoder(stdcfg)
}

// SetLevel 设置全局日志级别（仅影响标准输出）。
func SetLevel(lvl zapcore.Level) {
	core := zapcore.NewTee(zapcore.NewCore(
		zapcore.NewJSONEncoder(stdcfg),
		zapcore.Lock(os.Stdout),
		zap.NewAtomicLevelAt(lvl)))
	logger = zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1)).Sugar()
}

// Close 关闭所有日志 Writer（如日志文件轮转）。
func Close() {
	for _, c := range closerList {
		c.Close()
	}
}
