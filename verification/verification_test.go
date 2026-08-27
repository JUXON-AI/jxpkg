package verification

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"
)

type fakeStore struct {
	// reserveFn 模拟挑战预留行为。
	reserveFn func(context.Context, SendInput, string, Policy) error

	// verifyFn 模拟验证码核验行为。
	verifyFn func(context.Context, VerifyInput, Policy) error
}

func (s *fakeStore) Reserve(ctx context.Context, input SendInput, code string, policy Policy) error {
	if s.reserveFn == nil {
		return nil
	}
	return s.reserveFn(ctx, input, code, policy)
}

func (s *fakeStore) VerifyAndConsume(ctx context.Context, input VerifyInput, policy Policy) error {
	if s.verifyFn == nil {
		return nil
	}
	return s.verifyFn(ctx, input, policy)
}

type fakeDeliverer struct {
	// deliverFn 模拟验证码投递行为。
	deliverFn func(context.Context, Delivery) error
}

func (d *fakeDeliverer) Deliver(ctx context.Context, delivery Delivery) error {
	if d.deliverFn == nil {
		return nil
	}
	return d.deliverFn(ctx, delivery)
}

func validPolicy() Policy {
	return Policy{
		CodeLength:     6,
		CodeTTL:        5 * time.Minute,
		ResendCooldown: time.Minute,
		MaxAttempts:    5,
		TargetLimit:    5,
		TargetWindow:   time.Hour,
		IPLimit:        20,
		IPWindow:       time.Hour,
	}
}

func validSendInput() SendInput {
	return SendInput{
		Purpose:     Purpose("registration"),
		Channel:     ChannelEmail,
		Destination: "person@example.com",
		ClientIP:    "192.0.2.1",
	}
}

func TestGenerateCode(t *testing.T) {
	pattern := regexp.MustCompile(`^[0-9]{6}$`)
	for range 100 {
		code, err := generateCode()
		if err != nil {
			t.Fatalf("generateCode() error = %v", err)
		}
		if !pattern.MatchString(code) {
			t.Fatalf("generateCode() = %q, want exactly six ASCII digits", code)
		}
	}
}

func TestPolicyValidate(t *testing.T) {
	tests := []struct {
		// name 表示测试场景名称。
		name string

		// mutate 修改基础策略以构造测试输入。
		mutate func(*Policy)

		// wantErr 表示是否预期策略校验失败。
		wantErr bool
	}{
		{name: "valid", mutate: func(*Policy) {}},
		{name: "non-six code", mutate: func(policy *Policy) { policy.CodeLength = 8 }, wantErr: true},
		{name: "short ttl", mutate: func(policy *Policy) { policy.CodeTTL = time.Millisecond }, wantErr: true},
		{name: "cooldown exceeds ttl", mutate: func(policy *Policy) { policy.ResendCooldown = 10 * time.Minute }, wantErr: true},
		{name: "zero attempts", mutate: func(policy *Policy) { policy.MaxAttempts = 0 }, wantErr: true},
		{name: "zero target limit", mutate: func(policy *Policy) { policy.TargetLimit = 0 }, wantErr: true},
		{name: "zero IP window", mutate: func(policy *Policy) { policy.IPWindow = 0 }, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := validPolicy()
			test.mutate(&policy)
			err := policy.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, test.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("Validate() error = %v, want ErrInvalidPolicy", err)
			}
		})
	}
}

func TestServiceSend(t *testing.T) {
	input := validSendInput()
	now := time.Date(2026, time.August, 16, 12, 0, 0, 0, time.UTC)
	currentNow := now
	reserved := false
	delivered := false
	store := &fakeStore{reserveFn: func(_ context.Context, got SendInput, code string, policy Policy) error {
		reserved = true
		if got != input {
			t.Fatalf("Reserve() input = %#v, want %#v", got, input)
		}
		if !regexp.MustCompile(`^[0-9]{6}$`).MatchString(code) {
			t.Fatalf("Reserve() code format is invalid")
		}
		currentNow = now.Add(time.Minute)
		return nil
	}}
	deliverer := &fakeDeliverer{deliverFn: func(_ context.Context, delivery Delivery) error {
		delivered = true
		if !reserved {
			t.Fatal("Deliver() called before Reserve()")
		}
		if delivery.Destination != input.Destination || delivery.Code == "" {
			t.Fatal("Deliver() received incomplete delivery")
		}
		if want := now.Add(validPolicy().CodeTTL); !delivery.ExpiresAt.Equal(want) {
			t.Fatalf("Deliver() expiry = %v, want %v", delivery.ExpiresAt, want)
		}
		return nil
	}}
	service, err := NewService(store, deliverer, validPolicy())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	service.now = func() time.Time { return currentNow }
	if err := service.Send(context.Background(), input); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if !delivered {
		t.Fatal("Deliver() was not called")
	}
}

func TestServiceSendKeepsReservationOnDeliveryFailure(t *testing.T) {
	reserveCalls := 0
	store := &fakeStore{reserveFn: func(context.Context, SendInput, string, Policy) error {
		reserveCalls++
		return nil
	}}
	deliverer := &fakeDeliverer{deliverFn: func(context.Context, Delivery) error {
		return errors.New("provider rejected message")
	}}
	service, err := NewService(store, deliverer, validPolicy())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	err = service.Send(context.Background(), validSendInput())
	if !errors.Is(err, ErrDeliveryFailed) {
		t.Fatalf("Send() error = %v, want ErrDeliveryFailed", err)
	}
	if reserveCalls != 1 {
		t.Fatalf("Reserve() calls = %d, want 1", reserveCalls)
	}
}

func TestServiceSanitizesStoreError(t *testing.T) {
	store := &fakeStore{reserveFn: func(context.Context, SendInput, string, Policy) error {
		return errors.New("internal error containing sensitive input")
	}}
	service, err := NewService(store, &fakeDeliverer{}, validPolicy())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	err = service.Send(context.Background(), validSendInput())
	if err != ErrStore {
		t.Fatalf("Send() error = %v, want sanitized ErrStore", err)
	}
}

func TestServiceValidation(t *testing.T) {
	tests := []struct {
		// name 表示测试场景名称。
		name string

		// input 表示待验证的发送输入。
		input SendInput

		// want 表示预期的稳定领域错误。
		want error
	}{
		{name: "purpose", input: SendInput{Purpose: "Bad Purpose", Channel: ChannelEmail, Destination: "person@example.com", ClientIP: "192.0.2.1"}, want: ErrInvalidPurpose},
		{name: "channel", input: SendInput{Purpose: "registration", Channel: "fax", Destination: "person@example.com", ClientIP: "192.0.2.1"}, want: ErrInvalidChannel},
		{name: "email must be canonical", input: SendInput{Purpose: "registration", Channel: ChannelEmail, Destination: "Person@example.com", ClientIP: "192.0.2.1"}, want: ErrInvalidDestination},
		{name: "phone must be E.164", input: SendInput{Purpose: "registration", Channel: ChannelPhone, Destination: "13800138000", ClientIP: "192.0.2.1"}, want: ErrInvalidDestination},
		{name: "IP must be canonical", input: SendInput{Purpose: "registration", Channel: ChannelEmail, Destination: "person@example.com", ClientIP: "192.000.2.1"}, want: ErrInvalidClientIP},
	}
	service, err := NewService(&fakeStore{}, &fakeDeliverer{}, validPolicy())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := service.Send(context.Background(), test.input)
			if !errors.Is(err, test.want) {
				t.Fatalf("Send() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestServiceVerifyAndConsume(t *testing.T) {
	want := ErrCodeMismatch
	store := &fakeStore{verifyFn: func(_ context.Context, input VerifyInput, _ Policy) error {
		if input.Code != "012345" {
			t.Fatalf("VerifyAndConsume() code was changed")
		}
		return want
	}}
	service, err := NewService(store, &fakeDeliverer{}, validPolicy())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	err = service.VerifyAndConsume(context.Background(), VerifyInput{
		Purpose:     "registration",
		Channel:     ChannelEmail,
		Destination: "person@example.com",
		Code:        "012345",
	})
	if !errors.Is(err, want) {
		t.Fatalf("VerifyAndConsume() error = %v, want %v", err, want)
	}
}
