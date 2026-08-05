package settings

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

var secretAESKey string

const secretEncryptedPrefix = "encryped:"
const minSecretKeyLen = 16

func init() {
	skey := os.Getenv("GOAR_SETTINGS_SECRET_AES_KEY")
	if skey != "" {
		if len(skey) < minSecretKeyLen {
			panic(fmt.Sprintf("GOAR_SETTINGS_SECRET_AES_KEY length must be at least %d", minSecretKeyLen))
		}
		SetSecretAESKey(skey)
	}
}

// SetSecretAESKey 设置 AES-GCM 加密密钥，长度至少 16 字节。
func SetSecretAESKey(key string) {
	if len(key) < minSecretKeyLen {
		panic(fmt.Sprintf("secret AES key length must be at least %d", minSecretKeyLen))
	}
	secretAESKey = key
}

// EncryptSecret 使用 AES-GCM 加密明文。已加密（带 encryped: 前缀）的数据不会重复加密。
func EncryptSecret(oriData string) string {
	if secretAESKey == "" || strings.HasPrefix(oriData, secretEncryptedPrefix) {
		return oriData
	}
	encrypted, err := aesGCMEncryptToBase64([]byte(secretAESKey), []byte(oriData))
	if err != nil {
		return oriData
	}
	return secretEncryptedPrefix + encrypted
}

// DecryptSecret 解密 AES-GCM 密文。未加密的原始数据直接返回。
func DecryptSecret(encData string) string {
	if secretAESKey == "" || !strings.HasPrefix(encData, secretEncryptedPrefix) {
		return encData
	}
	oriData := strings.TrimPrefix(encData, secretEncryptedPrefix)
	decrypted, err := aesGCMDecryptFromBase64([]byte(secretAESKey), oriData)
	if err != nil {
		return encData
	}
	return string(decrypted)
}

func aesGCMEncryptToBase64(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func aesGCMDecryptFromBase64(key []byte, cryptoText string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
