// Package verification 提供与邮件、手机等投递通道无关的一次性验证码能力。
package verification

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

// Channel 表示验证码的投递通道。
type Channel string

const (
	// ChannelEmail 表示通过电子邮件投递验证码。
	ChannelEmail Channel = "email"

	// ChannelPhone 表示通过手机投递验证码。
	ChannelPhone Channel = "phone"

	// currentCodeLength 表示当前验证码固定使用六位数字。
	currentCodeLength = 6
)

var (
	// ErrInvalidPolicy 表示验证码策略不合法。
	ErrInvalidPolicy = errors.New("invalid verification policy")

	// ErrInvalidPurpose 表示验证码用途为空或格式不合法。
	ErrInvalidPurpose = errors.New("invalid verification purpose")

	// ErrInvalidChannel 表示验证码投递通道不受支持。
	ErrInvalidChannel = errors.New("invalid verification channel")

	// ErrInvalidDestination 表示投递地址不是对应通道的规范格式。
	ErrInvalidDestination = errors.New("invalid verification destination")

	// ErrInvalidClientIP 表示客户端 IP 不是规范的 IPv4 或 IPv6 地址。
	ErrInvalidClientIP = errors.New("invalid verification client IP")

	// ErrInvalidCode 表示待核验验证码格式不合法。
	ErrInvalidCode = errors.New("invalid verification code")

	// ErrResendCooldown 表示投递目标尚处于重发冷却期。
	ErrResendCooldown = errors.New("verification resend cooldown active")

	// ErrTargetRateLimited 表示投递目标已达到当前窗口的发送上限。
	ErrTargetRateLimited = errors.New("verification target rate limit exceeded")

	// ErrIPRateLimited 表示客户端 IP 已达到当前窗口的发送上限。
	ErrIPRateLimited = errors.New("verification IP rate limit exceeded")

	// ErrChallengeNotFound 表示验证码挑战不存在或已经过期。
	ErrChallengeNotFound = errors.New("verification challenge not found")

	// ErrCodeMismatch 表示验证码不匹配且仍可继续尝试。
	ErrCodeMismatch = errors.New("verification code mismatch")

	// ErrAttemptsExceeded 表示错误次数已达到上限且挑战已删除。
	ErrAttemptsExceeded = errors.New("verification attempts exceeded")

	// ErrDeliveryFailed 表示投递结果不确定或投递服务明确失败。
	ErrDeliveryFailed = errors.New("verification delivery failed")

	// ErrCodeGenerationFailed 表示安全随机验证码生成失败。
	ErrCodeGenerationFailed = errors.New("verification code generation failed")

	// ErrStore 表示验证码存储操作失败。
	ErrStore = errors.New("verification store failed")
)

var purposePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
var phonePattern = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)

// Purpose 表示验证码的业务用途；调用方应使用稳定、小写的用途标识。
type Purpose string

// Policy 定义验证码生命周期、尝试次数和发送频率策略。
type Policy struct {
	// CodeLength 表示数字验证码长度；当前服务固定要求为 6。
	CodeLength int

	// CodeTTL 表示验证码挑战的有效期。
	CodeTTL time.Duration

	// ResendCooldown 表示同一目标再次发送前的冷却时间。
	ResendCooldown time.Duration

	// MaxAttempts 表示验证码失效前允许的错误尝试次数。
	MaxAttempts int

	// TargetLimit 表示同一目标在固定窗口内允许的发送次数。
	TargetLimit int

	// TargetWindow 表示目标发送限流的固定窗口长度。
	TargetWindow time.Duration

	// IPLimit 表示同一客户端 IP 在固定窗口内允许的发送次数。
	IPLimit int

	// IPWindow 表示客户端 IP 发送限流的固定窗口长度。
	IPWindow time.Duration
}

// Validate 校验策略范围以及当前实现的六位验证码约束。
func (p Policy) Validate() error {
	if p.CodeLength < 4 || p.CodeLength > 10 || p.CodeLength != currentCodeLength {
		return ErrInvalidPolicy
	}
	if p.CodeTTL < time.Second || p.CodeTTL > 30*time.Minute {
		return ErrInvalidPolicy
	}
	if p.ResendCooldown < time.Second || p.ResendCooldown > p.CodeTTL {
		return ErrInvalidPolicy
	}
	if p.MaxAttempts < 1 || p.MaxAttempts > 20 {
		return ErrInvalidPolicy
	}
	if p.TargetLimit < 1 || p.TargetLimit > 10000 || p.TargetWindow < time.Second || p.TargetWindow > 24*time.Hour {
		return ErrInvalidPolicy
	}
	if p.IPLimit < 1 || p.IPLimit > 100000 || p.IPWindow < time.Second || p.IPWindow > 24*time.Hour {
		return ErrInvalidPolicy
	}
	return nil
}

// SendInput 描述一次验证码发送请求。
type SendInput struct {
	// Purpose 表示本次验证码的业务用途。
	Purpose Purpose

	// Channel 表示验证码的投递通道。
	Channel Channel

	// Destination 表示已规范化的邮件地址或 E.164 手机号。
	Destination string

	// ClientIP 表示已规范化的客户端 IPv4 或 IPv6 地址。
	ClientIP string
}

// VerifyInput 描述一次验证码核验请求。
type VerifyInput struct {
	// Purpose 表示待核验验证码的业务用途。
	Purpose Purpose

	// Channel 表示待核验验证码的投递通道。
	Channel Channel

	// Destination 表示已规范化的邮件地址或 E.164 手机号。
	Destination string

	// Code 表示用户提交的数字验证码。
	Code string
}

// Delivery 描述交给具体通道投递的验证码内容。
type Delivery struct {
	// Purpose 表示验证码的业务用途。
	Purpose Purpose

	// Channel 表示验证码的投递通道。
	Channel Channel

	// Destination 表示已规范化的投递地址。
	Destination string

	// Code 表示需要投递的明文数字验证码。
	Code string

	// ExpiresAt 表示验证码预计失效的时间。
	ExpiresAt time.Time
}

// Deliverer 由邮件、短信等具体通道实现验证码投递。
type Deliverer interface {
	// Deliver 投递验证码；实现不得在错误中包含验证码或投递地址。
	Deliver(ctx context.Context, delivery Delivery) error
}

// Store 定义验证码挑战的原子保存与核验消费能力。
type Store interface {
	// Reserve 原子执行冷却和限流检查，并保存明文验证码挑战。
	Reserve(ctx context.Context, input SendInput, code string, policy Policy) error

	// VerifyAndConsume 原子核验验证码；错误时累计次数，成功时立即消费。
	VerifyAndConsume(ctx context.Context, input VerifyInput, policy Policy) error
}

// Service 提供验证码发送和核验编排。
type Service struct {
	// store 保存并原子消费验证码挑战。
	store Store

	// deliverer 执行具体通道的验证码投递。
	deliverer Deliverer

	// policy 保存当前服务使用的验证码策略。
	policy Policy

	// now 提供可替换的当前时间，便于确定投递过期时间。
	now func() time.Time
}

// NewService 使用指定存储、投递器和策略创建验证码服务。
func NewService(store Store, deliverer Deliverer, policy Policy) (*Service, error) {
	if store == nil || deliverer == nil {
		return nil, ErrInvalidPolicy
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &Service{
		store:     store,
		deliverer: deliverer,
		policy:    policy,
		now:       time.Now,
	}, nil
}

// Send 校验输入、预留挑战和频率额度，然后投递验证码。
func (s *Service) Send(ctx context.Context, input SendInput) error {
	if err := validateSendInput(input); err != nil {
		return err
	}
	expiresAt := s.now().Add(s.policy.CodeTTL)
	code, err := generateCode()
	if err != nil {
		return ErrCodeGenerationFailed
	}
	if err := s.store.Reserve(ctx, input, code, s.policy); err != nil {
		return sanitizeStoreError(err, ErrResendCooldown, ErrTargetRateLimited, ErrIPRateLimited)
	}
	delivery := Delivery{
		Purpose:     input.Purpose,
		Channel:     input.Channel,
		Destination: input.Destination,
		Code:        code,
		ExpiresAt:   expiresAt,
	}
	if err := s.deliverer.Deliver(ctx, delivery); err != nil {
		return ErrDeliveryFailed
	}
	return nil
}

// VerifyAndConsume 校验输入，并通过存储原子核验和消费验证码。
func (s *Service) VerifyAndConsume(ctx context.Context, input VerifyInput) error {
	if err := validateVerifyInput(input, s.policy.CodeLength); err != nil {
		return err
	}
	return sanitizeStoreError(
		s.store.VerifyAndConsume(ctx, input, s.policy),
		ErrChallengeNotFound,
		ErrCodeMismatch,
		ErrAttemptsExceeded,
	)
}

func generateCode() (string, error) {
	code := make([]byte, currentCodeLength)
	randomBytes := make([]byte, currentCodeLength)
	for position := 0; position < len(code); {
		if _, err := rand.Read(randomBytes); err != nil {
			return "", err
		}
		for _, value := range randomBytes {
			// 250 是不大于 255 且能被 10 整除的最大边界，拒绝其余值可消除取模偏差。
			if value >= 250 {
				continue
			}
			code[position] = '0' + value%10
			position++
			if position == len(code) {
				break
			}
		}
	}
	return string(code), nil
}

func sanitizeStoreError(err error, allowed ...error) error {
	if err == nil {
		return nil
	}
	for _, candidate := range allowed {
		if errors.Is(err, candidate) {
			return candidate
		}
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return ErrStore
}

func validateSendInput(input SendInput) error {
	if err := validateIdentity(input.Purpose, input.Channel, input.Destination); err != nil {
		return err
	}
	ip := net.ParseIP(input.ClientIP)
	if ip == nil || ip.String() != input.ClientIP {
		return ErrInvalidClientIP
	}
	return nil
}

func validateVerifyInput(input VerifyInput, codeLength int) error {
	if err := validateIdentity(input.Purpose, input.Channel, input.Destination); err != nil {
		return err
	}
	if len(input.Code) != codeLength {
		return ErrInvalidCode
	}
	for i := range input.Code {
		if input.Code[i] < '0' || input.Code[i] > '9' {
			return ErrInvalidCode
		}
	}
	return nil
}

func validateIdentity(purpose Purpose, channel Channel, destination string) error {
	if !purposePattern.MatchString(string(purpose)) {
		return ErrInvalidPurpose
	}
	switch channel {
	case ChannelEmail:
		address, err := mail.ParseAddress(destination)
		if err != nil || address.Address != destination || strings.ToLower(destination) != destination {
			return ErrInvalidDestination
		}
	case ChannelPhone:
		if !phonePattern.MatchString(destination) {
			return ErrInvalidDestination
		}
	default:
		return ErrInvalidChannel
	}
	return nil
}
