package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
)

// ErrPrivateConfiguration 隐藏私有配置的路径、内容和解析错误。
var ErrPrivateConfiguration = errors.New("private JSON configuration unavailable or invalid")

// LoadPrivateJSON 读取至多 32 KiB 的私有普通文件，拒绝宽权限、重复键和未知字段。
// 符号链接必须指向普通文件；此检查防止误传特殊文件，不防御能够替换本机文件的特权主体。
func LoadPrivateJSON(path string, out any) (err error) {
	info, e := os.Stat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 32768 {
		return ErrPrivateConfiguration
	}
	file, e := os.Open(path)
	if e != nil {
		return ErrPrivateConfiguration
	}
	defer func() {
		if file.Close() != nil {
			err = ErrPrivateConfiguration
		}
	}()
	info, e = file.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 32768 {
		return ErrPrivateConfiguration
	}
	raw, e := io.ReadAll(io.LimitReader(file, 32769))
	if e != nil || len(raw) > 32768 {
		return ErrPrivateConfiguration
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, e := decoder.Token()
	if e != nil || token != json.Delim('{') {
		return ErrPrivateConfiguration
	}
	if uniqueObject(decoder, 0) != nil {
		return ErrPrivateConfiguration
	}
	if _, e = decoder.Token(); e != io.EOF {
		return ErrPrivateConfiguration
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrPrivateConfiguration
	}
	return nil
}
func uniqueObject(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrPrivateConfiguration
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, e := decoder.Token()
		name, ok := token.(string)
		if e != nil || !ok || seen[name] {
			return ErrPrivateConfiguration
		}
		for previous := range seen {
			if strings.EqualFold(previous, name) {
				return ErrPrivateConfiguration
			}
		}
		seen[name] = true
		if uniqueValue(decoder, depth+1) != nil {
			return ErrPrivateConfiguration
		}
	}
	token, e := decoder.Token()
	if e != nil || token != json.Delim('}') {
		return ErrPrivateConfiguration
	}
	return nil
}
func uniqueValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrPrivateConfiguration
	}
	token, e := decoder.Token()
	if e != nil {
		return ErrPrivateConfiguration
	}
	switch token {
	case json.Delim('{'):
		return uniqueObject(decoder, depth)
	case json.Delim('['):
		for decoder.More() {
			if uniqueValue(decoder, depth+1) != nil {
				return ErrPrivateConfiguration
			}
		}
		closing, e := decoder.Token()
		if e != nil || closing != json.Delim(']') {
			return ErrPrivateConfiguration
		}
	}
	return nil
}
