package logs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

type loggerWrapper struct {
	logger *zap.SugaredLogger
	levels []zap.AtomicLevel
}

type loggerRegistry struct {
	loggers        map[string]*loggerWrapper
	defaultWrapper *loggerWrapper
	closers        []io.Closer
}

var (
	registry atomic.Pointer[loggerRegistry]
	reloadMu sync.Mutex

	standardEncoderConfig = zapcore.EncoderConfig{
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

	accessEncoderConfig = zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "lvl",
		NameKey:        "reqid",
		CallerKey:      "caller",
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
	r, err := buildRegistry("-", nil)
	if err != nil {
		panic(err)
	}
	registry.Store(r)
}

// ReloadConfig 原子替换全部命名日志器的配置。
func ReloadConfig(module string, cfg LogsConfig) error {
	next, err := buildRegistry(module, cfg)
	if err != nil {
		return err
	}

	reloadMu.Lock()
	previous := registry.Swap(next)
	err = releaseRegistry(previous)
	reloadMu.Unlock()
	return err
}

func buildRegistry(module string, cfg LogsConfig) (*loggerRegistry, error) {
	r := &loggerRegistry{loggers: make(map[string]*loggerWrapper)}

	for name, outputs := range cfg {
		wrapper, closers, err := buildLogger(module, name, outputs)
		if err != nil {
			closeAll(r.closers)
			return nil, fmt.Errorf("build logger %q: %w", name, err)
		}
		r.loggers[name] = wrapper
		r.closers = append(r.closers, closers...)
	}

	switch {
	case r.loggers["default"] != nil:
		r.defaultWrapper = r.loggers["default"]
	case r.loggers["main"] != nil:
		r.defaultWrapper = r.loggers["main"]
		r.loggers["default"] = r.defaultWrapper
	default:
		wrapper, closers, err := buildLogger(module, "default", []LogConfig{defaultLogConfig})
		if err != nil {
			closeAll(r.closers)
			return nil, err
		}
		r.defaultWrapper = wrapper
		r.loggers["default"] = wrapper
		r.closers = append(r.closers, closers...)
	}

	return r, nil
}

func buildLogger(module, name string, outputs []LogConfig) (*loggerWrapper, []io.Closer, error) {
	if len(outputs) == 0 {
		outputs = []LogConfig{defaultLogConfig}
	}

	cores := make([]zapcore.Core, 0, len(outputs))
	levels := make([]zap.AtomicLevel, 0, len(outputs))
	closers := make([]io.Closer, 0, len(outputs))
	for i, output := range outputs {
		encoder, err := newEncoder(output.Encoder)
		if err != nil {
			closeAll(closers)
			return nil, nil, fmt.Errorf("output %d: %w", i, err)
		}

		syncer, closer, err := newWriteSyncer(output)
		if err != nil {
			closeAll(closers)
			return nil, nil, fmt.Errorf("output %d: %w", i, err)
		}
		if closer != nil {
			closers = append(closers, closer)
		}

		level := zap.NewAtomicLevelAt(output.Level)
		levels = append(levels, level)
		cores = append(cores, zapcore.NewCore(encoder, syncer, level))
	}

	fields := make([]zap.Field, 0, 2)
	if module != "" && module != "-" {
		fields = append(fields, zap.String("module", module))
	}
	if name != "" && name != "default" {
		fields = append(fields, zap.String("logger", name))
	}

	l := zap.New(
		zapcore.NewTee(cores...),
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
		zap.Fields(fields...),
	).Sugar()
	return &loggerWrapper{logger: l, levels: levels}, closers, nil
}

func newEncoder(name string) (zapcore.Encoder, error) {
	switch name {
	case "", "default", "json", EncoderStandard:
		return zapcore.NewJSONEncoder(standardEncoderConfig), nil
	case EncoderAccess:
		return zapcore.NewJSONEncoder(accessEncoderConfig), nil
	case EncoderConsole:
		return zapcore.NewConsoleEncoder(standardEncoderConfig), nil
	default:
		return nil, fmt.Errorf("unsupported logger encoder %q", name)
	}
}

func newWriteSyncer(cfg LogConfig) (zapcore.WriteSyncer, io.Closer, error) {
	switch cfg.Writer {
	case "", WriterConsole, WriterStdout:
		return zapcore.Lock(os.Stdout), nil, nil
	case WriterStderr:
		return zapcore.Lock(os.Stderr), nil, nil
	case WriterFile:
		if cfg.Logger == nil || cfg.Filename == "" {
			return nil, nil, errors.New("file writer requires filename")
		}
		file := cloneFileLogger(cfg.Logger)
		return zapcore.AddSync(file), file, nil
	default:
		return nil, nil, fmt.Errorf("unsupported logger writer %q", cfg.Writer)
	}
}

func cloneFileLogger(src *lumberjack.Logger) *lumberjack.Logger {
	return &lumberjack.Logger{
		Filename:   src.Filename,
		MaxSize:    src.MaxSize,
		MaxAge:     src.MaxAge,
		MaxBackups: src.MaxBackups,
		LocalTime:  src.LocalTime,
		Compress:   src.Compress,
	}
}

// Get 获取指定名称的日志器；名称不存在时返回默认日志器的同名子日志器。
func Get(name string) *zap.SugaredLogger {
	r := registry.Load()
	if wrapper := r.loggers[name]; wrapper != nil {
		return wrapper.logger
	}
	if name == "" || name == "default" {
		return r.defaultWrapper.logger
	}
	return r.defaultWrapper.logger.Named(name)
}

// With 返回附加结构化字段后的默认日志器。
func With(args ...interface{}) *zap.SugaredLogger { return Get("default").With(args...) }

// Desugar 返回默认日志器底层的 Zap Logger。
func Desugar() *zap.Logger { return Get("default").Desugar() }

// Named 返回默认日志器的命名子日志器。
func Named(name string) *zap.SugaredLogger { return Get("default").Named(name) }

// RequestLogger 返回以请求 ID 命名的访问日志器。
func RequestLogger(requestID string) *zap.SugaredLogger {
	return Get("access").Named(requestID)
}

// SetLevel 设置默认日志器全部输出的日志级别。
func SetLevel(level zapcore.Level) {
	for _, atomicLevel := range registry.Load().defaultWrapper.levels {
		atomicLevel.SetLevel(level)
	}
}

// Sync 刷新全部已配置日志器的缓冲区。
func Sync() error { return syncRegistry(registry.Load()) }

// Close 刷新并关闭已配置的文件输出，然后恢复默认控制台日志器，
// 确保后续日志调用仍然安全。
func Close() {
	fallback, err := buildRegistry("-", nil)
	if err != nil {
		return
	}

	reloadMu.Lock()
	previous := registry.Swap(fallback)
	_ = releaseRegistry(previous)
	reloadMu.Unlock()
}

func releaseRegistry(r *loggerRegistry) error {
	if r == nil {
		return nil
	}
	return errors.Join(syncRegistry(r), closeAll(r.closers))
}

func syncRegistry(r *loggerRegistry) error {
	if r == nil {
		return nil
	}
	seen := make(map[*zap.SugaredLogger]struct{}, len(r.loggers))
	var errs []error
	for _, wrapper := range r.loggers {
		if _, ok := seen[wrapper.logger]; ok {
			continue
		}
		seen[wrapper.logger] = struct{}{}
		if err := wrapper.logger.Sync(); !ignorableSyncError(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func ignorableSyncError(err error) bool {
	return err == nil || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTTY) || errors.Is(err, syscall.EBADF)
}

func closeAll(closers []io.Closer) error {
	var errs []error
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func callerLogger(l *zap.SugaredLogger) *zap.SugaredLogger {
	return l.Desugar().WithOptions(zap.AddCallerSkip(1)).Sugar()
}

func Debug(args ...interface{}) { callerLogger(Get("default")).Debug(args...) }
func Info(args ...interface{})  { callerLogger(Get("default")).Info(args...) }
func Warn(args ...interface{})  { callerLogger(Get("default")).Warn(args...) }
func Error(args ...interface{}) { callerLogger(Get("default")).Error(args...) }
func Fatal(args ...interface{}) { callerLogger(Get("default")).Fatal(args...) }

func Debugf(template string, args ...interface{}) {
	callerLogger(Get("default")).Debugf(template, args...)
}
func Infof(template string, args ...interface{}) {
	callerLogger(Get("default")).Infof(template, args...)
}
func Warnf(template string, args ...interface{}) {
	callerLogger(Get("default")).Warnf(template, args...)
}
func Errorf(template string, args ...interface{}) {
	callerLogger(Get("default")).Errorf(template, args...)
}
func Fatalf(template string, args ...interface{}) {
	callerLogger(Get("default")).Fatalf(template, args...)
}

func Debugw(msg string, keysAndValues ...interface{}) {
	callerLogger(Get("default")).Debugw(msg, keysAndValues...)
}
func Infow(msg string, keysAndValues ...interface{}) {
	callerLogger(Get("default")).Infow(msg, keysAndValues...)
}
func Warnw(msg string, keysAndValues ...interface{}) {
	callerLogger(Get("default")).Warnw(msg, keysAndValues...)
}
func Errorw(msg string, keysAndValues ...interface{}) {
	callerLogger(Get("default")).Errorw(msg, keysAndValues...)
}
func Fatalw(msg string, keysAndValues ...interface{}) {
	callerLogger(Get("default")).Fatalw(msg, keysAndValues...)
}
