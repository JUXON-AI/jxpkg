package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	// maximumJOSEHeaderBytes 限制解码后的受保护 JOSE 头大小。
	maximumJOSEHeaderBytes = 16 * 1024

	// maximumJWTClaimsBytes 限制解码后的 JWT 声明大小。
	maximumJWTClaimsBytes = 1024 * 1024

	// maximumJSONNestingDepth 限制 JOSE 头和声明中的 JSON 容器嵌套深度。
	maximumJSONNestingDepth = 32
)

// validateCompactJSONObjects 在 JWT 库解析前严格检查受保护头和声明 JSON。
func validateCompactJSONObjects(raw string) error {
	segments := strings.Split(raw, ".")
	if len(segments) != 3 {
		return fmt.Errorf("compact JWT must contain exactly three segments")
	}
	limits := [...]int{maximumJOSEHeaderBytes, maximumJWTClaimsBytes}
	for index, limit := range limits {
		document, err := decodeCompactSegment(segments[index], limit)
		if err != nil {
			return fmt.Errorf("decode compact segment %d: %w", index+1, err)
		}
		if err := validateJSONObject(document); err != nil {
			return fmt.Errorf("validate compact segment %d: %w", index+1, err)
		}
	}
	return nil
}

func decodeCompactSegment(segment string, maximumBytes int) ([]byte, error) {
	if segment == "" {
		return nil, fmt.Errorf("segment is empty")
	}
	if len(segment) > base64.RawURLEncoding.EncodedLen(maximumBytes) {
		return nil, fmt.Errorf("decoded segment exceeds %d bytes", maximumBytes)
	}
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(segment)))
	count, err := base64.RawURLEncoding.Strict().Decode(decoded, []byte(segment))
	if err != nil {
		return nil, fmt.Errorf("invalid base64url: %w", err)
	}
	if count > maximumBytes {
		return nil, fmt.Errorf("decoded segment exceeds %d bytes", maximumBytes)
	}
	return decoded[:count], nil
}

func validateJSONObject(document []byte) error {
	if !utf8.Valid(document) {
		return fmt.Errorf("JSON is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	opening, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if opening != json.Delim('{') {
		return fmt.Errorf("JSON root must be an object")
	}
	if err := consumeJSONObject(decoder, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("JSON contains trailing values")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return nil
}

func consumeJSONObject(decoder *json.Decoder, depth int) error {
	if depth > maximumJSONNestingDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maximumJSONNestingDepth)
	}
	members := make(map[string]struct{})
	for decoder.More() {
		memberToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("read object member: %w", err)
		}
		member, ok := memberToken.(string)
		if !ok {
			return fmt.Errorf("object member name is not a string")
		}
		if _, exists := members[member]; exists {
			return fmt.Errorf("duplicate object member %q", member)
		}
		members[member] = struct{}{}
		if err := consumeJSONValue(decoder, depth); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("close object: %w", err)
	}
	if closing != json.Delim('}') {
		return fmt.Errorf("object has invalid closing delimiter")
	}
	return nil
}

func consumeJSONArray(decoder *json.Decoder, depth int) error {
	if depth > maximumJSONNestingDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maximumJSONNestingDepth)
	}
	for decoder.More() {
		if err := consumeJSONValue(decoder, depth); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("close array: %w", err)
	}
	if closing != json.Delim(']') {
		return fmt.Errorf("array has invalid closing delimiter")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, parentDepth int) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("read JSON value: %w", err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return consumeJSONObject(decoder, parentDepth+1)
	case '[':
		return consumeJSONArray(decoder, parentDepth+1)
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}
