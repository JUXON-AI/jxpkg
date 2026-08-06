package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/JUXON-AI/jxpkg/config"
)

// 连接Minoss
func TestNewMinBucketClient(t *testing.T) {
	var defaultCfg = config.MinossConfig{
		EndPoint:        os.Getenv("END_POINT"),
		AccessKeyID:     os.Getenv("ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("SECRET_ACCESS_KEY_ID"),
		Bucket:          "default-bucket",
	}
	if defaultCfg.EndPoint == "" || defaultCfg.AccessKeyID == "" || defaultCfg.SecretAccessKey == "" {
		t.Skip("skip test, no minoss config")
		return
	}
	mc, err := NewMinFs(defaultCfg, config.StorageOption{})
	if err != nil {
		fmt.Println(err)
		t.Log(err)
		//t.Fail()

	}
	t.Logf("%+v", mc)
}

func TestMinBucketClient_UploadFile(t *testing.T) {
	var defaultCfg = config.MinossConfig{
		EndPoint:        os.Getenv("END_POINT"),
		AccessKeyID:     os.Getenv("ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("SECRET_ACCESS_KEY_ID"),
		Bucket:          "default-bucket",
	}
	if defaultCfg.EndPoint == "" || defaultCfg.AccessKeyID == "" || defaultCfg.SecretAccessKey == "" {
		t.Skip("skip test, no minoss config")
		return
	}
	mc, err := NewMinFs(defaultCfg, config.StorageOption{})
	if err != nil {
		t.Log(err)
	}
	content := []byte("this is a test")
	path := "test/a/test.txt"
	if err := mc.Save(context.Background(), &FileInfo{StoragePath: path, Size: int64(len(content))}, bytes.NewBuffer(content)); err != nil {
		t.Log(err)
	}
}

func TestMinBucketClient_GetPresignedURL(t *testing.T) {
	var defaultCfg = config.MinossConfig{
		EndPoint:        os.Getenv("END_POINT"),
		AccessKeyID:     os.Getenv("ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("SECRET_ACCESS_KEY_ID"),
		Bucket:          "default-bucket",
	}
	if defaultCfg.EndPoint == "" || defaultCfg.AccessKeyID == "" || defaultCfg.SecretAccessKey == "" {
		t.Skip("skip test, no minoss config")
		return
	}
	mc, err := NewMinFs(defaultCfg, config.StorageOption{})
	if err != nil {
		t.Log(err)
	}
	path := "test/a/test.txt"
	url, err := mc.GetPresignedURL(http.MethodGet, path)
	if err != nil {
		t.Log(err)
	}
	fmt.Println(url)
}

func TestMinBucketClient_ReadFile(t *testing.T) {
	var defaultCfg = config.MinossConfig{
		EndPoint:        os.Getenv("END_POINT"),
		AccessKeyID:     os.Getenv("ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("SECRET_ACCESS_KEY_ID"),
		Bucket:          "default-bucket",
	}
	if defaultCfg.EndPoint == "" || defaultCfg.AccessKeyID == "" || defaultCfg.SecretAccessKey == "" {
		t.Skip("skip test, no minoss config")
		return
	}
	mc, err := NewMinFs(defaultCfg, config.StorageOption{})
	if err != nil {
		t.Log(err)
	}
	path := "test/a/test.txt"
	file, err := mc.ReadFile(path)
	if err != nil {
		t.Log(err)
	}
	data, _ := io.ReadAll(file)
	fmt.Println(string(data))
}

func TestMinBucketClient_DeleteFile(t *testing.T) {
	var defaultCfg = config.MinossConfig{
		EndPoint:        os.Getenv("END_POINT"),
		AccessKeyID:     os.Getenv("ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("SECRET_ACCESS_KEY_ID"),
		Bucket:          "default-bucket",
	}
	if defaultCfg.EndPoint == "" || defaultCfg.AccessKeyID == "" || defaultCfg.SecretAccessKey == "" {
		t.Skip("skip test, no minoss config")
		return
	}
	mc, err := NewMinFs(defaultCfg, config.StorageOption{})
	if err != nil {
		t.Log(err)
	}
	path := "test/a/test.txt"
	err = mc.DeleteFile(path)
	if err != nil {
		t.Log(err)
	}
}

func TestMinBucketClient_CopyDir(t *testing.T) {
	var defaultCfg = config.MinossConfig{
		EndPoint:        os.Getenv("END_POINT"),
		AccessKeyID:     os.Getenv("ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("SECRET_ACCESS_KEY_ID"),
		Bucket:          "default-bucket",
	}
	if defaultCfg.EndPoint == "" || defaultCfg.AccessKeyID == "" || defaultCfg.SecretAccessKey == "" {
		t.Skip("skip test, no minoss config")
		return
	}
	mc, err := NewMinFs(defaultCfg, config.StorageOption{})
	if err != nil {
		t.Log(err)
	}
	path := "test/a"
	err = mc.CopyDir(path, "test/b")
	if err != nil {
		t.Log(err)
	}
}
