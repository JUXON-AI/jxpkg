// Package mail 提供仅依赖 Go 标准库的 SMTP 邮件发送能力。
package mail

import (
	"context"
	"errors"
	"fmt"
	"net"
	stdmail "net/mail"
	"strings"
	"time"
)

// Encryption 表示 SMTP 连接使用的传输加密方式。
type Encryption string

const (
	// EncryptionSTARTTLS 表示先建立明文 SMTP 连接，再通过 STARTTLS 升级为 TLS。
	EncryptionSTARTTLS Encryption = "starttls"

	// EncryptionTLS 表示从连接建立开始即使用隐式 TLS。
	EncryptionTLS Encryption = "tls"

	// EncryptionNone 表示使用不加密的 SMTP 连接，仅允许无凭据发送。
	EncryptionNone Encryption = "none"

	// defaultTimeout 表示未配置超时时单次 SMTP 发送的默认时限。
	defaultTimeout = 30 * time.Second
)

var (
	// ErrInvalidConfig 表示 SMTP 配置缺少必要值或包含不安全值。
	ErrInvalidConfig = errors.New("invalid SMTP configuration")

	// ErrInvalidMessage 表示邮件缺少必要内容或包含不安全的头字段。
	ErrInvalidMessage = errors.New("invalid mail message")

	// ErrDelivery 表示 SMTP 连接或投递过程失败。
	ErrDelivery = errors.New("mail delivery failed")
)

// Config 表示 SMTP 服务器及发件人配置。
type Config struct {
	// Host 表示 SMTP 服务器主机名或 IP 地址，不包含端口。
	Host string `yaml:"host"`

	// Port 表示 SMTP 服务端口，取值范围为 1 至 65535。
	Port int `yaml:"port"`

	// Username 表示 SMTP AUTH PLAIN 用户名；匿名发送时留空。
	Username string `yaml:"username"`

	// Password 表示 SMTP AUTH PLAIN 密码；匿名发送时留空。
	Password string `yaml:"password"`

	// From 表示符合 RFC 5322 地址格式的发件人，可包含显示名称。
	From string `yaml:"from"`

	// Encryption 表示连接使用 starttls、tls 或 none。
	Encryption Encryption `yaml:"encryption"`

	// Timeout 表示包含连接、TLS 握手和投递在内的单次发送时限；零值使用三十秒。
	Timeout time.Duration `yaml:"timeout"`
}

// Message 表示待发送邮件的收件人、主题和可选的纯文本及 HTML 正文。
type Message struct {
	// To 表示一个或多个符合 RFC 5322 地址格式的收件人。
	To []string

	// Subject 表示邮件主题，不允许包含回车或换行符。
	Subject string

	// Text 表示纯文本正文；与 HTML 同时存在时构建 multipart/alternative。
	Text string

	// HTML 表示 HTML 正文；与 Text 同时存在时构建 multipart/alternative。
	HTML string
}

// Sender 定义可替换的邮件投递能力。
type Sender interface {
	// Send 使用调用方上下文投递一封邮件。
	Send(ctx context.Context, message Message) error
}

// Validate 检查 SMTP 配置完整性和传输安全约束。
func (config Config) Validate() error {
	if !validHost(config.Host) {
		return fmt.Errorf("%w: invalid host", ErrInvalidConfig)
	}
	if config.Port < 1 || config.Port > 65535 {
		return fmt.Errorf("%w: invalid port", ErrInvalidConfig)
	}
	if config.Timeout < 0 {
		return fmt.Errorf("%w: invalid timeout", ErrInvalidConfig)
	}
	if hasHeaderBreak(config.From) {
		return fmt.Errorf("%w: invalid from address", ErrInvalidConfig)
	}
	if _, err := parseAddress(config.From); err != nil {
		return fmt.Errorf("%w: invalid from address", ErrInvalidConfig)
	}
	if (config.Username == "") != (config.Password == "") {
		return fmt.Errorf("%w: incomplete credentials", ErrInvalidConfig)
	}
	switch config.Encryption {
	case EncryptionSTARTTLS, EncryptionTLS:
	case EncryptionNone:
		if config.Username != "" {
			return fmt.Errorf("%w: credentials require encryption", ErrInvalidConfig)
		}
	default:
		return fmt.Errorf("%w: invalid encryption", ErrInvalidConfig)
	}
	return nil
}

func (message Message) validate() error {
	if len(message.To) == 0 {
		return fmt.Errorf("%w: missing recipients", ErrInvalidMessage)
	}
	for _, recipient := range message.To {
		if hasHeaderBreak(recipient) {
			return fmt.Errorf("%w: invalid recipient", ErrInvalidMessage)
		}
		if _, err := parseAddress(recipient); err != nil {
			return fmt.Errorf("%w: invalid recipient", ErrInvalidMessage)
		}
	}
	if strings.TrimSpace(message.Subject) == "" || hasHeaderBreak(message.Subject) {
		return fmt.Errorf("%w: invalid subject", ErrInvalidMessage)
	}
	if message.Text == "" && message.HTML == "" {
		return fmt.Errorf("%w: missing body", ErrInvalidMessage)
	}
	return nil
}

func parseAddress(value string) (*stdmail.Address, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("empty address")
	}
	return stdmail.ParseAddress(value)
}

func hasHeaderBreak(value string) bool {
	return strings.ContainsAny(value, "\r\n")
}

func validHost(host string) bool {
	if host == "" || len(host) > 253 || strings.TrimSpace(host) != host || strings.ContainsAny(host, "\r\n\t ") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	host = strings.TrimSuffix(host, ".")
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}
