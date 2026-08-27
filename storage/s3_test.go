package storage

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"testing"
)

// TestNewS3Fs 连接S3存储 测试通过：minio cos
func TestNewS3Fs(t *testing.T) {
	ctx := context.Background()
	defaultCfg := testS3Config(t)
	s3c, err := NewS3Fs(ctx, defaultCfg, StorageOption{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", s3c)
}

// TestS3FsSave 保存文件 测试通过：minio cos
func TestS3FsSave(t *testing.T) {
	defaultCfg := testS3Config(t)
	s3c, err := NewS3Fs(context.Background(), defaultCfg, StorageOption{})
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("this is a test")
	// 腾讯云会更改文件内容
	path := "test/a/test1.txt"
	if err := s3c.Save(context.Background(), &CoreFileInfo{StoragePath: path, Size: int64(len(content))}, bytes.NewBuffer(content)); err != nil {
		t.Fatal(err)
	}
}

// TestS3FsGetPresignedURL 预上传预下载 测试通过：minio cos
func TestS3FsGetPresignedURL(t *testing.T) {
	defaultCfg := testS3Config(t)
	s3c, err := NewS3Fs(context.Background(), defaultCfg, StorageOption{})
	if err != nil {
		t.Fatal(err)
	}
	path := "test/a/test1.txt"
	url, err := s3c.GetPresignedURL(context.Background(), http.MethodGet, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(url)
}

// TestS3FsReadFile 读取文件 测试通过：minio cos
func TestS3FsReadFile(t *testing.T) {
	defaultCfg := testS3Config(t)
	s3c, err := NewS3Fs(context.Background(), defaultCfg, StorageOption{})
	if err != nil {
		t.Fatal(err)
	}
	path := "test/a/test1.txt"
	// file, err := s3c.ReadFile(path)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// data, _ := io.ReadAll(file)
	// fmt.Println(string(data))
	t.Log(s3c.GetPublicURL(context.Background(), path))
}

// TestS3FsDeleteFile 删除 测试通过：minio cos
func TestS3FsDeleteFile(t *testing.T) {
	defaultCfg := testS3Config(t)
	s3c, err := NewS3Fs(context.Background(), defaultCfg, StorageOption{})
	if err != nil {
		t.Fatal(err)
	}
	path := "test/a/test1.txt"
	err = s3c.DeleteFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
}

func testS3Config(t *testing.T) S3StorageConfig {
	t.Helper()
	cfg := S3StorageConfig{
		EndPoint:        os.Getenv("JXPKG_TEST_S3_ENDPOINT"),
		AccessKeyID:     os.Getenv("JXPKG_TEST_S3_ACCESS_KEY"),
		SecretAccessKey: os.Getenv("JXPKG_TEST_S3_SECRET_KEY"),
		Bucket:          os.Getenv("JXPKG_TEST_S3_BUCKET"),
		Region:          os.Getenv("JXPKG_TEST_S3_REGION"),
	}
	if cfg.EndPoint == "" || cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" || cfg.Bucket == "" {
		t.Skip("skip object storage integration test: JXPKG_TEST_S3_* is incomplete")
	}
	return cfg
}
