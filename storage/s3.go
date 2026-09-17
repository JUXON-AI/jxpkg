package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	s3config "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

var _ Storager = (*S3Fs)(nil)
var _ MultipartStorager = (*S3Fs)(nil)

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

// CreateMultipartUpload 创建一个私有对象的分片上传会话。
func (s3fs *S3Fs) CreateMultipartUpload(ctx context.Context, storagePath, contentType string) (string, error) {
	if strings.TrimSpace(storagePath) == "" {
		return "", fmt.Errorf("storage path is empty")
	}
	input := &s3.CreateMultipartUploadInput{
		Bucket: aws.String(s3fs.s3fsCfg.Bucket),
		Key:    aws.String(storagePath),
	}
	if strings.TrimSpace(contentType) != "" {
		input.ContentType = aws.String(contentType)
	}
	result, err := s3fs.client.CreateMultipartUpload(ctx, input)
	if err != nil {
		return "", err
	}
	uploadID := strings.TrimSpace(aws.ToString(result.UploadId))
	if uploadID == "" {
		return "", fmt.Errorf("multipart upload ID is empty")
	}
	return uploadID, nil
}

// GetMultipartUploadPartPresignedURL 返回单个分片的预签名 PUT URL。
func (s3fs *S3Fs) GetMultipartUploadPartPresignedURL(ctx context.Context, storagePath, uploadID string, partNumber int32) (string, error) {
	if err := validateMultipartReference(storagePath, uploadID, partNumber); err != nil {
		return "", err
	}
	result, err := s3.NewPresignClient(s3fs.client).PresignUploadPart(ctx, &s3.UploadPartInput{
		Bucket:     aws.String(s3fs.s3fsCfg.Bucket),
		Key:        aws.String(storagePath),
		UploadId:   aws.String(uploadID),
		PartNumber: aws.Int32(partNumber),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = s3fs.opt.PresignedTimeout
	})
	if err != nil {
		return "", err
	}
	return result.URL, nil
}

// ListMultipartUploadParts 返回对象存储中已经接收的全部分片。
func (s3fs *S3Fs) ListMultipartUploadParts(ctx context.Context, storagePath, uploadID string) ([]MultipartUploadPart, error) {
	if err := validateMultipartReference(storagePath, uploadID, 1); err != nil {
		return nil, err
	}
	paginator := s3.NewListPartsPaginator(s3fs.client, &s3.ListPartsInput{
		Bucket:   aws.String(s3fs.s3fsCfg.Bucket),
		Key:      aws.String(storagePath),
		UploadId: aws.String(uploadID),
	})
	parts := make([]MultipartUploadPart, 0)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, part := range page.Parts {
			parts = append(parts, MultipartUploadPart{
				PartNumber: aws.ToInt32(part.PartNumber),
				ETag:       normalizeETag(aws.ToString(part.ETag)),
			})
		}
	}
	return parts, nil
}

// CompleteMultipartUpload 按分片序号合并已上传对象。
func (s3fs *S3Fs) CompleteMultipartUpload(ctx context.Context, storagePath, uploadID string, parts map[int32]string) error {
	if err := validateMultipartReference(storagePath, uploadID, 1); err != nil {
		return err
	}
	completed, err := completedMultipartParts(parts)
	if err != nil {
		return err
	}
	_, err = s3fs.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(s3fs.s3fsCfg.Bucket),
		Key:      aws.String(storagePath),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completed,
		},
	})
	return err
}

// AbortMultipartUpload 终止未完成的分片上传并释放对象存储资源。
func (s3fs *S3Fs) AbortMultipartUpload(ctx context.Context, storagePath, uploadID string) error {
	if err := validateMultipartReference(storagePath, uploadID, 1); err != nil {
		return err
	}
	_, err := s3fs.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket: aws.String(s3fs.s3fsCfg.Bucket), Key: aws.String(storagePath), UploadId: aws.String(uploadID),
	})
	return err
}

func validateMultipartReference(storagePath, uploadID string, partNumber int32) error {
	if strings.TrimSpace(storagePath) == "" {
		return fmt.Errorf("storage path is empty")
	}
	if strings.TrimSpace(uploadID) == "" {
		return fmt.Errorf("multipart upload ID is empty")
	}
	if partNumber < 1 || partNumber > 10000 {
		return fmt.Errorf("multipart part number must be between 1 and 10000")
	}
	return nil
}

func completedMultipartParts(parts map[int32]string) ([]types.CompletedPart, error) {
	if len(parts) == 0 || len(parts) > 10000 {
		return nil, fmt.Errorf("multipart parts count is invalid")
	}
	values := make([]MultipartUploadPart, 0, len(parts))
	for partNumber, etag := range parts {
		values = append(values, MultipartUploadPart{PartNumber: partNumber, ETag: etag})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].PartNumber < values[j].PartNumber })
	completed := make([]types.CompletedPart, 0, len(values))
	for _, part := range values {
		etag := normalizeETag(part.ETag)
		if part.PartNumber < 1 || part.PartNumber > 10000 || etag == "" {
			return nil, fmt.Errorf("multipart part is invalid")
		}
		completed = append(completed, types.CompletedPart{
			PartNumber: aws.Int32(part.PartNumber),
			ETag:       aws.String(`"` + etag + `"`),
		})
	}
	return completed, nil
}

func normalizeETag(value string) string {
	return strings.Trim(strings.TrimSpace(value), `"`)
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
