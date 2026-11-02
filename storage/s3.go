package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
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
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

var _ Storager = (*S3Fs)(nil)
var _ MultipartStorager = (*S3Fs)(nil)
var _ OriginalFileStorager = (*S3Fs)(nil)

const originalImageCIQuery = "originImage"

// originalFileHTTPClient deliberately does not follow redirects. A redirected
// signed GET could forward its credential-bearing query string to another host.
var originalFileHTTPClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// S3StorageConfig S3通用存储
type S3StorageConfig struct {
	EndPoint        string `yaml:"end_point"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	Region          string `yaml:"region"`
	Bucket          string `yaml:"bucket"`
	UsePathStyle    bool   `yaml:"use_path_style"` // 是否使用路径风格的URL minio true 腾讯云 false
	// OriginalImageCI enables the provider's billable original-image operation
	// (COS ci-process=originImage). It must remain false for providers without
	// that operation.
	OriginalImageCI bool `yaml:"original_image_ci"`
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

// OriginalFileSupported reports whether this instance opted into the provider's
// billable original-image operation.
func (s3fs *S3Fs) OriginalFileSupported() bool {
	return s3fs != nil && s3fs.s3fsCfg.OriginalImageCI
}

// originalImageQueryMiddleware adds the provider query before the SDK signing
// middleware runs. The request path and all other query parameters stay owned
// by the SDK; this code deliberately does not rebuild the object URL.
type originalImageQueryMiddleware struct{}

func (*originalImageQueryMiddleware) ID() string { return "C660OriginalImageQuery" }

func (*originalImageQueryMiddleware) HandleBuild(
	ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler,
) (middleware.BuildOutput, middleware.Metadata, error) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return middleware.BuildOutput{}, middleware.Metadata{},
			fmt.Errorf("original image query: unexpected request type %T", in.Request)
	}
	query := request.URL.Query()
	query.Set("ci-process", originalImageCIQuery)
	request.URL.RawQuery = query.Encode()
	return next.HandleBuild(ctx, in)
}

func addOriginalImageQuery(stack *middleware.Stack) error {
	return stack.Build.Add(&originalImageQueryMiddleware{}, middleware.After)
}

func (s3fs *S3Fs) presignOriginalObject(
	ctx context.Context, storagePath string, optFns ...func(*s3.PresignOptions),
) (*v4.PresignedHTTPRequest, error) {
	presigner := s3.NewPresignClient(s3fs.client, func(options *s3.PresignOptions) {
		options.Expires = s3fs.opt.PresignedTimeout
		options.ClientOptions = append(options.ClientOptions, func(options *s3.Options) {
			options.APIOptions = append(options.APIOptions, addOriginalImageQuery)
		})
	})
	return presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s3fs.s3fsCfg.Bucket),
		Key:    aws.String(storagePath),
	}, optFns...)
}

// GetPresignedOriginalURL signs a GET for the provider's original-image API.
// The query is inserted through an SDK build middleware so the normal
// PresignGetObject signing flow, path encoding, and unsigned payload semantics
// remain authoritative.
func (s3fs *S3Fs) GetPresignedOriginalURL(ctx context.Context, method, storagePath string) (string, error) {
	if !s3fs.OriginalFileSupported() {
		return "", fmt.Errorf("original image CI is not enabled")
	}
	if method != http.MethodGet {
		return "", fmt.Errorf("original file URL only supports GET, now: %s", method)
	}
	if strings.TrimSpace(storagePath) == "" {
		return "", fmt.Errorf("storage path is empty")
	}
	result, err := s3fs.presignOriginalObject(ctx, storagePath)
	if err != nil {
		return "", fmt.Errorf("sign original object URL: %w", err)
	}
	return result.URL, nil
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

// ReadOriginalFile streams the object through the provider's original-image
// endpoint. The caller remains responsible for size, hash, and media checks.
func (s3fs *S3Fs) ReadOriginalFile(ctx context.Context, storagePath string) (io.ReadCloser, error) {
	signedURL, err := s3fs.GetPresignedOriginalURL(ctx, http.MethodGet, storagePath)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, signedURL, nil)
	if err != nil {
		// A URL parse error can contain the signed query string. Do not wrap it.
		return nil, fmt.Errorf("build original object request: invalid signed address")
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := originalFileHTTPClient.Do(request)
	if err != nil {
		return nil, originalReadTransportError(err)
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, fmt.Errorf("read original object: status %d", response.StatusCode)
	}
	if response.Body == nil {
		return nil, fmt.Errorf("read original object: empty body")
	}
	return response.Body, nil
}

// originalReadTransportError removes url.Error, which contains the complete
// signed URL, while preserving cancellation identity and a safe error category.
func originalReadTransportError(err error) error {
	if err == nil {
		return nil
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Err == nil {
			return errors.New("read original object: transport failure")
		}
		err = urlErr.Err
	}
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("read original object: canceled: %w", context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("read original object: deadline exceeded: %w", context.DeadlineExceeded)
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return fmt.Errorf("read original object: network timeout: %w", context.DeadlineExceeded)
		}
		return errors.New("read original object: network failure")
	}
	return errors.New("read original object: transport failure")
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
