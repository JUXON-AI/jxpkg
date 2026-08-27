package mail

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
)

// SMTPSender 使用 SMTP AUTH PLAIN 和配置的传输加密方式发送邮件。
type SMTPSender struct {
	// config 保存已经通过校验的 SMTP 配置。
	config Config
}

// NewSMTPSender 校验配置并创建标准库 SMTP 发送器，不会立即建立网络连接。
func NewSMTPSender(config Config) (*SMTPSender, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &SMTPSender{config: config}, nil
}

// Send 在上下文和配置时限内投递邮件，并支持多个 SMTP 信封收件人。
func (sender *SMTPSender) Send(ctx context.Context, message Message) error {
	if sender == nil {
		return fmt.Errorf("%w: sender is nil", ErrInvalidConfig)
	}
	payload, err := buildMessage(sender.config, message)
	if err != nil {
		return err
	}

	timeout := sender.config.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	operationCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, connection, err := sender.connect(operationCtx)
	if err != nil {
		return sender.operationError(operationCtx, "connect SMTP server", err)
	}
	defer client.Close()

	stopCancellation := make(chan struct{})
	defer close(stopCancellation)
	go func() {
		select {
		case <-operationCtx.Done():
			_ = connection.Close()
		case <-stopCancellation:
		}
	}()

	if sender.config.Encryption == EncryptionSTARTTLS {
		if err := client.StartTLS(sender.tlsConfig()); err != nil {
			return sender.operationError(operationCtx, "start TLS", err)
		}
	}
	if sender.config.Username != "" {
		auth := smtp.PlainAuth("", sender.config.Username, sender.config.Password, sender.config.Host)
		if err := client.Auth(auth); err != nil {
			return sender.operationError(operationCtx, "authenticate", err)
		}
	}

	from, _ := parseAddress(sender.config.From)
	if err := client.Mail(from.Address); err != nil {
		return sender.operationError(operationCtx, "set sender", err)
	}
	for _, value := range message.To {
		recipient, _ := parseAddress(value)
		if err := client.Rcpt(recipient.Address); err != nil {
			return sender.operationError(operationCtx, "set recipient", err)
		}
	}
	data, err := client.Data()
	if err != nil {
		return sender.operationError(operationCtx, "open message body", err)
	}
	if _, err := data.Write(payload); err != nil {
		_ = data.Close()
		return sender.operationError(operationCtx, "write message body", err)
	}
	if err := data.Close(); err != nil {
		return sender.operationError(operationCtx, "commit message body", err)
	}
	if err := client.Quit(); err != nil {
		return sender.operationError(operationCtx, "close SMTP session", err)
	}
	return nil
}

func (sender *SMTPSender) connect(ctx context.Context) (*smtp.Client, net.Conn, error) {
	address := net.JoinHostPort(sender.config.Host, strconv.Itoa(sender.config.Port))
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			_ = connection.Close()
			return nil, nil, err
		}
	}

	if sender.config.Encryption == EncryptionTLS {
		tlsConnection := tls.Client(connection, sender.tlsConfig())
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			_ = connection.Close()
			return nil, nil, err
		}
		connection = tlsConnection
	}
	client, err := smtp.NewClient(connection, sender.config.Host)
	if err != nil {
		_ = connection.Close()
		return nil, nil, err
	}
	return client, connection, nil
}

func (sender *SMTPSender) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: sender.config.Host,
	}
}

func (sender *SMTPSender) operationError(ctx context.Context, operation string, _ error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("%w: %s: %w", ErrDelivery, operation, ctxErr)
	}
	return fmt.Errorf("%w: %s", ErrDelivery, operation)
}

var _ Sender = (*SMTPSender)(nil)
