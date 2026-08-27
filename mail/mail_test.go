package mail

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	stdmail "net/mail"
	"strings"
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		// name 表示测试场景名称。
		name string

		// mutate 修改基础配置以构造当前场景。
		mutate func(config *Config)
	}{
		{name: "valid starttls", mutate: func(_ *Config) {}},
		{name: "missing host", mutate: func(config *Config) { config.Host = "" }},
		{name: "malformed host", mutate: func(config *Config) { config.Host = "smtp/example.com" }},
		{name: "invalid port", mutate: func(config *Config) { config.Port = 0 }},
		{name: "invalid from", mutate: func(config *Config) { config.From = "not-an-address" }},
		{name: "from injection", mutate: func(config *Config) { config.From = "sender@example.com\r\nBcc: victim@example.com" }},
		{name: "incomplete credentials", mutate: func(config *Config) { config.Password = "" }},
		{name: "credentials without encryption", mutate: func(config *Config) { config.Encryption = EncryptionNone }},
		{name: "unknown encryption", mutate: func(config *Config) { config.Encryption = "ssl" }},
		{name: "negative timeout", mutate: func(config *Config) { config.Timeout = -time.Second }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig()
			test.mutate(&config)
			err := config.Validate()
			if test.name == "valid starttls" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Validate() error = %v, want ErrInvalidConfig", err)
			}
		})
	}

	anonymous := validConfig()
	anonymous.Username = ""
	anonymous.Password = ""
	anonymous.Encryption = EncryptionNone
	if err := anonymous.Validate(); err != nil {
		t.Fatalf("anonymous unencrypted Validate() error = %v", err)
	}
}

func TestBuildMessageMultipartAlternative(t *testing.T) {
	payload, err := buildMessage(validConfig(), Message{
		To:      []string{"First <first@example.com>", "second@example.com"},
		Subject: "Juxonone 验证",
		Text:    "plain code: 123456",
		HTML:    "<strong>123456</strong>",
	})
	if err != nil {
		t.Fatalf("buildMessage() error = %v", err)
	}
	parsed, err := stdmail.ReadMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	addresses, err := parsed.Header.AddressList("To")
	if err != nil {
		t.Fatalf("AddressList(To) error = %v", err)
	}
	if len(addresses) != 2 {
		t.Fatalf("recipient count = %d, want 2", len(addresses))
	}

	mediaType, parameters, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("ParseMediaType() error = %v", err)
	}
	if mediaType != "multipart/alternative" {
		t.Fatalf("media type = %q, want multipart/alternative", mediaType)
	}
	reader := multipart.NewReader(parsed.Body, parameters["boundary"])
	wantBodies := []string{"plain code: 123456", "<strong>123456</strong>"}
	for index, want := range wantBodies {
		part, err := reader.NextPart()
		if err != nil {
			t.Fatalf("NextPart(%d) error = %v", index, err)
		}
		body, err := io.ReadAll(quotedprintable.NewReader(part))
		if err != nil {
			t.Fatalf("read part %d error = %v", index, err)
		}
		if string(body) != want {
			t.Errorf("part %d body = %q, want %q", index, body, want)
		}
	}
	if _, err := reader.NextPart(); err != io.EOF {
		t.Fatalf("final NextPart() error = %v, want EOF", err)
	}
}

func TestBuildMessageRejectsInvalidMessage(t *testing.T) {
	tests := []struct {
		// name 表示测试场景名称。
		name string

		// message 表示当前场景待构建的邮件。
		message Message
	}{
		{name: "missing recipient", message: Message{Subject: "subject", Text: "body"}},
		{name: "invalid recipient", message: Message{To: []string{"invalid"}, Subject: "subject", Text: "body"}},
		{name: "recipient injection", message: Message{To: []string{"to@example.com\r\nBcc: other@example.com"}, Subject: "subject", Text: "body"}},
		{name: "missing subject", message: Message{To: []string{"to@example.com"}, Text: "body"}},
		{name: "subject injection", message: Message{To: []string{"to@example.com"}, Subject: "subject\nBcc: other@example.com", Text: "body"}},
		{name: "missing body", message: Message{To: []string{"to@example.com"}, Subject: "subject"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := buildMessage(validConfig(), test.message)
			if !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("buildMessage() error = %v, want ErrInvalidMessage", err)
			}
		})
	}
}

func TestBuildMessageHTMLOnly(t *testing.T) {
	payload, err := buildMessage(validConfig(), Message{
		To:      []string{"to@example.com"},
		Subject: "subject",
		HTML:    "<p>Juxonone</p>",
	})
	if err != nil {
		t.Fatalf("buildMessage() error = %v", err)
	}
	if !strings.Contains(string(payload), "Content-Type: text/html; charset=UTF-8") {
		t.Fatalf("payload does not contain HTML content type: %q", payload)
	}
}

func validConfig() Config {
	return Config{
		Host:       "smtp.example.com",
		Port:       587,
		Username:   "mailer",
		Password:   "secret",
		From:       "Juxonone <no-reply@example.com>",
		Encryption: EncryptionSTARTTLS,
		Timeout:    5 * time.Second,
	}
}
