package storage

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/JUXON-AI/jxpkg/settings"
)

// StorageOption 对象存储通用配置选项
type StorageOption struct {
	// Purpose 是文件的用途,按业务分类
	Purpose string `yaml:"purpose"`
	// PresignedTimeout 预签名超时时间
	PresignedTimeout time.Duration `yaml:"presigned_timeout"`
}

// StorageConfig 对象存储配置
type StorageConfig struct {
	StorageOption `yaml:",inline"`

	S3 *S3StorageConfig `yaml:"s3,omitempty"`
}

// FileMetadata 表示对象存储返回的文件元数据。
type FileMetadata struct {
	// ContentLength 表示对象原始内容的字节数。
	ContentLength int64

	// ContentType 表示对象的 MIME 类型。
	ContentType string

	// ETag 表示对象内容的实体标签，通常对应单次上传对象的 MD5 值。
	ETag string
}

const (
	SettingGroupCore = "core"
	// SettingPrefix 配置前缀
	SettingPrefix = "storage-"
)

var storagerMap = new(sync.Map)

// Storager .
type Storager interface {
	Save(ctx context.Context, fi *CoreFileInfo, data io.Reader) error
	GetPublicURL(ctx context.Context, storagePath string) string
	GetPresignedURL(ctx context.Context, method, storagePath string) (string, error)
	HeadFile(ctx context.Context, storagePath string) (*FileMetadata, error)
	ReadFile(ctx context.Context, storagePath string) (io.ReadCloser, error)
	DeleteFile(ctx context.Context, storagePath string) error
}

// LoadStorager 获取存储器
func LoadStorager(ctx context.Context, purpose string) (Storager, error) {
	if s, ok := storagerMap.Load(purpose); ok {
		return s.(Storager), nil
	}
	s, err := NewStorage(ctx, purpose)
	if err != nil {
		return nil, err
	}
	storagerMap.Store(purpose, s)
	return s, nil
}

// NewStorage .
func NewStorage(ctx context.Context, purpose string) (Storager, error) {
	var (
		cfg StorageConfig
		s   Storager
		err error
		key = SettingPrefix + purpose
	)
	err = settings.GetYaml(SettingGroupCore, key, &cfg)
	if err != nil {
		logs.Errorf("get storage config error: %v", err)
		return nil, err
	}

	if cfg.S3 != nil {
		s, err = NewS3Fs(ctx, *cfg.S3, cfg.StorageOption)
	} else {
		return nil, fmt.Errorf("not found useful remote storage config")
	}
	if err != nil {
		logs.Errorf("new storage error: %v", err)
		return nil, err
	}
	return s, nil
}
