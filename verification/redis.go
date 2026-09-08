package verification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/redis/go-redis/v9"
)

const (
	// redisKeyPrefix 是验证码 Redis 键的版本化前缀和集群哈希标签。
	redisKeyPrefix = "core:verification:v1:{verification}:"

	// reserveScript 原子执行冷却、固定窗口限流和挑战保存。
	reserveScript = `
if redis.call('HEXISTS', KEYS[1], 'claim') == 1 then
  return 1
end

if redis.call('EXISTS', KEYS[2]) == 1 then
  return 1
end

local target_count = tonumber(redis.call('GET', KEYS[3]) or '0')
if target_count >= tonumber(ARGV[4]) then
  return 2
end

local ip_count = tonumber(redis.call('GET', KEYS[4]) or '0')
if ip_count >= tonumber(ARGV[6]) then
  return 3
end

target_count = redis.call('INCR', KEYS[3])
if target_count == 1 then
  redis.call('PEXPIRE', KEYS[3], ARGV[5])
end

ip_count = redis.call('INCR', KEYS[4])
if ip_count == 1 then
  redis.call('PEXPIRE', KEYS[4], ARGV[7])
end

redis.call('HSET', KEYS[1], 'code', ARGV[1], 'attempts', 0)
redis.call('PEXPIRE', KEYS[1], ARGV[2])
redis.call('SET', KEYS[2], '1', 'PX', ARGV[3])
return 0
`

	// verifyScript 原子核验验证码，并在成功或达到错误上限时删除挑战。
	verifyScript = `
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 1
end

local stored_code = redis.call('HGET', KEYS[1], 'code')
if not stored_code then
  redis.call('DEL', KEYS[1])
  return 1
end

if redis.call('HEXISTS', KEYS[1], 'claim') == 1 then
  return 4
end

if stored_code == ARGV[1] then
  redis.call('DEL', KEYS[1])
  return 0
end

local attempts = redis.call('HINCRBY', KEYS[1], 'attempts', 1)
if attempts >= tonumber(ARGV[2]) then
  redis.call('DEL', KEYS[1])
  return 3
end
return 2
`

	// verifyAndClaimScript 原子核验并领取挑战，同时保留挑战原始 TTL。
	verifyAndClaimScript = `
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 1
end

local stored_code = redis.call('HGET', KEYS[1], 'code')
if not stored_code then
  redis.call('DEL', KEYS[1])
  return 1
end

if redis.call('HEXISTS', KEYS[1], 'claim') == 1 then
  return 4
end

if stored_code == ARGV[1] then
  redis.call('HSET', KEYS[1], 'claim', ARGV[3])
  return 0
end

local attempts = redis.call('HINCRBY', KEYS[1], 'attempts', 1)
if attempts >= tonumber(ARGV[2]) then
  redis.call('DEL', KEYS[1])
  return 3
end
return 2
`

	// consumeClaimScript 仅允许持有匹配领取凭据的调用方删除挑战。
	consumeClaimScript = `
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 1
end
if redis.call('HGET', KEYS[1], 'claim') ~= ARGV[1] then
  return 5
end
redis.call('DEL', KEYS[1])
return 0
`

	// releaseClaimScript 仅移除匹配的领取字段，不改变挑战剩余 TTL 和错误次数。
	releaseClaimScript = `
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 1
end
if redis.call('HGET', KEYS[1], 'claim') ~= ARGV[1] then
  return 5
end
redis.call('HDEL', KEYS[1], 'claim')
return 0
`
)

// RedisStore 使用 Redis Lua 脚本原子保存和消费验证码挑战。
type RedisStore struct {
	// client 是由应用注入的 Redis 客户端。
	client *redis.Client

	// reserve 是原子预留挑战及限流额度的脚本。
	reserve *redis.Script

	// verify 是原子核验并消费挑战的脚本。
	verify *redis.Script

	// verifyAndClaimScript、consumeClaimScript 和 releaseClaimScript 构成可回滚的两阶段领取生命周期。
	verifyAndClaimScript *redis.Script
	consumeClaimScript   *redis.Script
	releaseClaimScript   *redis.Script
}

// NewRedisStore 使用应用提供的 Redis 客户端创建验证码存储。
func NewRedisStore(client *redis.Client) (*RedisStore, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: nil redis client", ErrStore)
	}
	return &RedisStore{
		client:               client,
		reserve:              redis.NewScript(reserveScript),
		verify:               redis.NewScript(verifyScript),
		verifyAndClaimScript: redis.NewScript(verifyAndClaimScript),
		consumeClaimScript:   redis.NewScript(consumeClaimScript),
		releaseClaimScript:   redis.NewScript(releaseClaimScript),
	}, nil
}

// Reserve 原子执行冷却和限流检查，并保存带有效期的明文验证码。
func (s *RedisStore) Reserve(ctx context.Context, input SendInput, code string, policy Policy) error {
	keys := redisKeys(input.Purpose, input.Channel, input.Destination, input.ClientIP)
	result, err := s.reserve.Run(ctx, s.client, keys, code, policy.CodeTTL.Milliseconds(), policy.ResendCooldown.Milliseconds(), policy.TargetLimit, policy.TargetWindow.Milliseconds(), policy.IPLimit, policy.IPWindow.Milliseconds()).Int64()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: reserve script failed", ErrStore)
	}
	return mapReserveResult(result)
}

// VerifyAndConsume 原子核验验证码，累计错误次数并按结果删除挑战。
func (s *RedisStore) VerifyAndConsume(ctx context.Context, input VerifyInput, policy Policy) error {
	key := challengeKey(input.Purpose, input.Channel, input.Destination)
	result, err := s.verify.Run(ctx, s.client, []string{key}, input.Code, policy.MaxAttempts).Int64()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: verify script failed", ErrStore)
	}
	return mapVerifyResult(result)
}

// verifyAndClaim 原子核验并领取挑战，成功时保留原始过期时间。
func (s *RedisStore) verifyAndClaim(ctx context.Context, input VerifyInput, policy Policy, claimToken string) error {
	key := challengeKey(input.Purpose, input.Channel, input.Destination)
	result, err := s.verifyAndClaimScript.Run(ctx, s.client, []string{key}, input.Code, policy.MaxAttempts, claimToken).Int64()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: verify-and-claim script failed", ErrStore)
	}
	return mapVerifyResult(result)
}

// consumeClaim 原子删除持有匹配领取凭据的挑战。
func (s *RedisStore) consumeClaim(ctx context.Context, purpose Purpose, channel Channel, destination, claimToken string) error {
	return s.runClaimMutation(ctx, s.consumeClaimScript, purpose, channel, destination, claimToken, "consume")
}

// releaseClaim 原子释放持有匹配领取凭据的挑战并保留其剩余 TTL。
func (s *RedisStore) releaseClaim(ctx context.Context, purpose Purpose, channel Channel, destination, claimToken string) error {
	return s.runClaimMutation(ctx, s.releaseClaimScript, purpose, channel, destination, claimToken, "release")
}

func (s *RedisStore) runClaimMutation(ctx context.Context, script *redis.Script, purpose Purpose, channel Channel, destination, claimToken, operation string) error {
	key := challengeKey(purpose, channel, destination)
	result, err := script.Run(ctx, s.client, []string{key}, claimToken).Int64()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: %s claim script failed", ErrStore, operation)
	}
	return mapClaimMutationResult(result)
}

func mapReserveResult(result int64) error {
	switch result {
	case 0:
		return nil
	case 1:
		return ErrResendCooldown
	case 2:
		return ErrTargetRateLimited
	case 3:
		return ErrIPRateLimited
	default:
		return fmt.Errorf("%w: unexpected reserve script result", ErrStore)
	}
}

func mapVerifyResult(result int64) error {
	switch result {
	case 0:
		return nil
	case 1:
		return ErrChallengeNotFound
	case 2:
		return ErrCodeMismatch
	case 3:
		return ErrAttemptsExceeded
	case 4:
		return ErrChallengeClaimed
	default:
		return fmt.Errorf("%w: unexpected verify script result", ErrStore)
	}
}

func mapClaimMutationResult(result int64) error {
	switch result {
	case 0:
		return nil
	case 1:
		return ErrChallengeNotFound
	case 5:
		return ErrInvalidClaim
	default:
		return fmt.Errorf("%w: unexpected claim mutation result", ErrStore)
	}
}

func redisKeys(purpose Purpose, channel Channel, destination, clientIP string) []string {
	destinationDigest := digest(destination)
	ipDigest := digest(clientIP)
	identity := string(purpose) + ":" + string(channel) + ":" + destinationDigest
	rateIdentity := string(purpose) + ":" + string(channel)
	return []string{
		redisKeyPrefix + "challenge:" + identity,
		redisKeyPrefix + "cooldown:" + identity,
		redisKeyPrefix + "target-rate:" + identity,
		redisKeyPrefix + "ip-rate:" + rateIdentity + ":" + ipDigest,
	}
}

func challengeKey(purpose Purpose, channel Channel, destination string) string {
	return redisKeyPrefix + "challenge:" + string(purpose) + ":" + string(channel) + ":" + digest(destination)
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
