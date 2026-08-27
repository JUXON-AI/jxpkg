package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	s3config "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var _ Storager = (*S3Fs)(nil)

// S3StorageConfig S3通用存储
type S3StorageConfig struct {
	EndPoint        string `yaml:"end_point"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	Region          string `yaml:"region"`
	Bucket          string `yaml:"bucket"`
	UsePathStyle    bool   `yaml:"use_path_style"` // 是否使用路径风格的URL minio true 腾讯云 false
}

// S3Fs .
type S3Fs struct {
	opt     StorageOption
	s3fsCfg S3StorageConfig
	client  *s3.Client
}

// NewS3Fs 初始化S3Fs
func NewS3Fs(ctx context.Context, cfg S3StorageConfig, opt StorageOption) (*S3Fs, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("configuration bucket error")
	}

	s3fs := &S3Fs{
		opt:     opt,
		s3fsCfg: cfg,
	}
	s3cfg, err := s3config.LoadDefaultConfig(ctx,
		s3config.WithRegion(cfg.Region),
		s3config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, "")),
	)
	if err != nil {
		return nil, err
	}

	s3fs.client = s3.NewFromConfig(s3cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(cfg.EndPoint) // 直接指定 endpoint URL
		o.UsePathStyle = cfg.UsePathStyle         // 使用路径风格的URL
		// 类似es配置可导入日志配置
	})
	// 检查存储桶是否存在
	_, err = s3fs.client.HeadBucket(ctx,
		&s3.HeadBucketInput{
			Bucket: aws.String(cfg.Bucket),
		})
	if err != nil {
		return nil, err
	}
	return s3fs, nil
}

// Save 保存文件
func (s3fs *S3Fs) Save(ctx context.Context, fi *CoreFileInfo, r io.Reader) error {
	if fi.StoragePath == "" {
		return fmt.Errorf("storage path is empty")
	}
	if r == nil {
		return fmt.Errorf("reader is empty")
	}
	uploader := manager.NewUploader(s3fs.client)
	_, err := uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s3fs.s3fsCfg.Bucket),
		Key:         aws.String(fi.StoragePath),
		Body:        r,
		ContentType: aws.String(mime.TypeByExtension(fi.FileExt)),
	})
	if err != nil {
		return err
	}
	return nil
}

// GetPublicURL 获取公共URL
func (s3fs *S3Fs) GetPublicURL(ctx context.Context, storagePath string) string {
	if storagePath == "" {
		return ""
	}
	url_obj, err := url.Parse(s3fs.s3fsCfg.EndPoint)
	if err != nil {
		return storagePath
	}
	if s3fs.s3fsCfg.UsePathStyle {
		// minio
		public_url, err := url.JoinPath(url_obj.Scheme+"://"+url_obj.Host, s3fs.s3fsCfg.Bucket, storagePath)
		if err != nil {
			return storagePath
		}
		return public_url
	}
	// cos
	public_url, err := url.JoinPath(url_obj.Scheme+"://"+s3fs.s3fsCfg.Bucket+"."+url_obj.Host, storagePath)
	if err != nil {
		return storagePath
	}
	// 官方方法
	// aa, _ := s3fs.client.Options().EndpointResolverV2.ResolveEndpoint(s3fs.ctx, s3.EndpointParameters{
	// 	Bucket:         aws.String(s3fs.s3fsCfg.Bucket),
	// 	Region:         aws.String(s3fs.s3fsCfg.Region),
	// 	Endpoint:       aws.String(s3fs.s3fsCfg.EndPoint),
	// 	ForcePathStyle: aws.Bool(s3fs.s3fsCfg.UsePathStyle),
	// })
	return public_url
}

// GetPresignedURL 获取预签名URL
func (s3fs *S3Fs) GetPresignedURL(ctx context.Context, method, storagePath string) (string, error) {
	presigner := s3.NewPresignClient(s3fs.client)
	var (
		err error
		url *v4.PresignedHTTPRequest
	)

	switch method {
	case http.MethodGet:
		url, err = presigner.PresignGetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(s3fs.s3fsCfg.Bucket),
			Key:    aws.String(storagePath),
		}, func(opts *s3.PresignOptions) {
			opts.Expires = s3fs.opt.PresignedTimeout // 链接有效期，默认15分钟，最大不能超过 7 天
		})
	case http.MethodPut:
		url, err = presigner.PresignPutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(s3fs.s3fsCfg.Bucket),
			Key:    aws.String(storagePath),
		}, func(opts *s3.PresignOptions) {
			opts.Expires = s3fs.opt.PresignedTimeout // 链接有效期，默认15分钟，最大不能超过 7 天
		})
	default:
		return "", fmt.Errorf("only GET and PUT are allowed,now: %s", method)
	}

	if err != nil {
		return "", err
	}

	return url.URL, nil
}

// HeadFile 获取对象的原始元数据，避免读取可能经过转换的对象内容。
func (s3fs *S3Fs) HeadFile(ctx context.Context, storagePath string) (*FileMetadata, error) {
	if storagePath == "" {
		return nil, fmt.Errorf("storage path is empty")
	}
	obj, err := s3fs.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s3fs.s3fsCfg.Bucket),
		Key:    aws.String(storagePath),
	})
	if err != nil {
		return nil, err
	}
	return &FileMetadata{
		ContentLength: aws.ToInt64(obj.ContentLength),
		ContentType:   aws.ToString(obj.ContentType),
		ETag:          strings.Trim(aws.ToString(obj.ETag), `"`),
	}, nil
}

// ReadFile 获取文件内容
func (s3fs *S3Fs) ReadFile(ctx context.Context, storagePath string) (io.ReadCloser, error) {
	if storagePath == "" {
		return nil, fmt.Errorf("storage path is empty")
	}
	obj, err := s3fs.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s3fs.s3fsCfg.Bucket),
		Key:    aws.String(storagePath),
	})
	if err != nil {
		return nil, err
	}
	return obj.Body, nil
}

// DeleteFile 删除文件
func (s3fs *S3Fs) DeleteFile(ctx context.Context, storagePath string) error {
	if storagePath == "" {
		return fmt.Errorf("storage path is empty")
	}
	_, err := s3fs.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s3fs.s3fsCfg.Bucket),
		Key:    aws.String(storagePath),
	})
	if err != nil {
		return err
	}
	return nil
}
