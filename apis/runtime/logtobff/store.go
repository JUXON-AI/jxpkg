package logtobff

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"time"

	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/redis/go-redis/v9"
)

var _errMissing = errors.New("session missing")
var _errBusy = errors.New("session busy")
var _errInvalid = errors.New("session invalid")

const (
	// sessionPolicyVersion 2 mirrors Account's tested eight-hour idle and
	// seven-day absolute browser-session policy.
	sessionPolicyVersion    uint64 = 2
	sessionIdleLifetime            = 8 * time.Hour
	sessionAbsoluteLifetime        = 7 * 24 * time.Hour
	sessionAcquireRetryMin         = 2 * time.Millisecond
	sessionAcquireRetryMax         = 25 * time.Millisecond
	sessionAcquireMissing   int64  = -1
	sessionAcquireBusy      int64  = 0
	sessionAcquireOwned     int64  = 1
)

// acquire's script reads the source before taking the lease so a missing or
// wrong-type record cannot create a new lock. The owner remains the fencing
// token used by commit and release, including when a late Eval response is lost.
const acquireScript = `
local data=redis.call('get',KEYS[2])
if not data then return {-1} end
if not redis.call('set',KEYS[1],ARGV[1],'NX','PX',ARGV[2]) then return {0} end
return {1,data}`

// Redis owns short-lived authentication capabilities only. Every value is encrypted;
// the key prefix is authenticated too, preventing transaction/session substitution.
type store struct {
	prefix  string
	db      *redis.Client
	box     cipher.AEAD
	entropy io.Reader
	now     func() time.Time
}
type session struct {
	SDK          map[string]string `json:"sdk"`
	Subject      string            `json:"subject"`
	Organization string            `json:"organization"`
	Revision     string            `json:"revision"`
	CSRF         string            `json:"csrf"`
	// Until is the pre-policy fixed expiry and remains the idle projection for
	// version 2 records so an earlier BFF can still read a newer record safely.
	Until           time.Time `json:"until"`
	PolicyVersion   uint64    `json:"policy_version,omitempty"`
	AuthenticatedAt time.Time `json:"authenticated_at,omitempty"`
	IdleUntil       time.Time `json:"idle_until,omitempty"`
	AbsoluteUntil   time.Time `json:"absolute_until,omitempty"`
}
type transaction struct {
	SDK      map[string]string `json:"sdk"`
	Nonce    string            `json:"nonce"`
	State    string            `json:"state"`
	ReturnTo string            `json:"return_to"`
	// Silent only changes how a validated provider error is rendered. It is not
	// browser-controlled authentication state and never creates a session.
	Silent bool `json:"silent,omitempty"`
}

func (s *store) opaque() (string, error) {
	data := make([]byte, 32)
	if _, err := io.ReadFull(s.entropy, data); err != nil {
		return "", errors.New("system entropy unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
func newStore(address, password, key, prefix string) (*store, error) {
	raw, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("invalid session encryption key")
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	box, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &store{db: redis.NewClient(&redis.Options{Addr: address, Password: password, DialTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second, MaxRetries: -1, PoolSize: 8, MaxActiveConns: 8, ContextTimeoutEnabled: true, PoolTimeout: time.Second}), box: box, prefix: prefix, entropy: rand.Reader, now: time.Now}, nil
}

func (s *store) nowTime() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

func validateSessionSchema(value *session, now time.Time) error {
	if value == nil {
		return _errInvalid
	}
	if value.PolicyVersion != sessionPolicyVersion ||
		value.AuthenticatedAt.IsZero() || value.AuthenticatedAt.After(now) || value.IdleUntil.IsZero() || value.AbsoluteUntil.IsZero() ||
		!value.Until.Equal(value.IdleUntil) || value.IdleUntil.Before(value.AuthenticatedAt) || value.IdleUntil.After(value.AbsoluteUntil) ||
		!value.AbsoluteUntil.Equal(value.AuthenticatedAt.Add(sessionAbsoluteLifetime)) {
		return _errInvalid
	}
	return nil
}

func sessionDeadline(value *session, now time.Time) (time.Time, error) {
	if err := validateSessionSchema(value, now); err != nil {
		return time.Time{}, err
	}
	deadline := value.IdleUntil
	if value.AbsoluteUntil.Before(deadline) {
		deadline = value.AbsoluteUntil
	}
	if !now.Before(deadline) {
		return time.Time{}, _errMissing
	}
	return deadline, nil
}

func nextSessionIdle(now, absolute time.Time) time.Time {
	next := now.Add(sessionIdleLifetime)
	if next.After(absolute) {
		return absolute
	}
	return next
}

func sessionCookieMaxAge(value *session, now time.Time) int {
	deadline, err := sessionCookieDeadline(value)
	if err != nil {
		return -1
	}
	remaining := deadline.Sub(now)
	if remaining <= 0 {
		return -1
	}
	return int((remaining + time.Second - 1) / time.Second)
}
func (s *store) seal(key string, value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(data) > 65536 {
		return nil, errors.New("authentication value too large")
	}
	nonce := make([]byte, s.box.NonceSize())
	if _, err = io.ReadFull(s.entropy, nonce); err != nil {
		return nil, err
	}
	return s.box.Seal(nonce, nonce, data, []byte(key)), nil
}
func (s *store) open(key string, data []byte, value any) error {
	n := s.box.NonceSize()
	if len(data) < n || len(data) > 66000 {
		return errors.New("invalid authentication value")
	}
	plain, err := s.box.Open(nil, data[:n], data[n:], []byte(key))
	if err != nil {
		return errors.New("authentication value integrity failure")
	}
	return json.Unmarshal(plain, value)
}
func (s *store) start(ctx context.Context, tx transaction) (string, transaction, error) {
	id, err := s.opaque()
	if err != nil {
		return "", tx, err
	}
	key := s.prefix + "tx:" + id
	data, err := s.seal(key, tx)
	if err != nil {
		return "", tx, err
	}
	err = s.db.Set(ctx, key, data, 5*time.Minute).Err()
	return id, tx, err
}
func (s *store) consume(ctx context.Context, id string) (transaction, error) {
	var tx transaction
	if !_opaquePattern.MatchString(id) {
		return tx, _errMissing
	}
	key := s.prefix + "tx:" + id
	data, err := s.db.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return tx, _errMissing
	}
	if err != nil {
		return tx, err
	}
	return tx, s.open(key, data, &tx)
}
func (s *store) create(ctx context.Context, value *session, previous string) (string, error) {
	now := s.nowTime()
	deadline, err := sessionDeadline(value, now)
	if err != nil {
		return "", err
	}
	id, err := s.opaque()
	if err != nil {
		return "", err
	}
	key := s.prefix + "s:" + id
	data, err := s.seal(key, value)
	if err != nil {
		return "", err
	}
	if !_opaquePattern.MatchString(previous) {
		previous = "absent"
	}
	return id, s.db.Eval(ctx, `redis.call('set',KEYS[1],ARGV[1],'PX',ARGV[2]);redis.call('del',KEYS[2]);return 1`, []string{key, s.prefix + "s:" + previous}, data, deadline.Sub(now).Milliseconds()).Err()
}

// A fixed 30s lease outlives the entire 20s request budget. All commits are fenced
// by lease ownership and source existence; a late writer cannot revive logout.
func (s *store) acquire(ctx context.Context, id string) (*session, string, error) {
	var (
		started   = time.Now()
		busyCount = 0
	)
	defer func() { recordIdentityPhase(ctx, "bff.lease.acquire", started, busyCount) }()
	if !_opaquePattern.MatchString(id) {
		return nil, "", _errMissing
	}
	owner, err := s.opaque()
	if err != nil {
		return nil, "", err
	}
	lock := s.prefix + "lock:" + id
	key := s.prefix + "s:" + id
	// Remote identity checks share the 20s authentication budget with this wait.
	deadline := time.Now().Add(_authenticationTimeout)
	for {
		result, err := s.db.Eval(ctx, acquireScript, []string{lock, key}, owner, (30 * time.Second).Milliseconds()).Slice()
		if err != nil {
			// Redis does not roll back commands that ran before a Lua error. The
			// owner fence makes cleanup safe when no lease, another owner's lease,
			// or this call's late lease is present.
			s.release(ctx, id, owner)
			return nil, "", err
		}
		if len(result) == 0 {
			s.release(ctx, id, owner)
			return nil, "", errors.New("acquire authentication session: invalid script response")
		}
		status, ok := result[0].(int64)
		if !ok {
			s.release(ctx, id, owner)
			return nil, "", errors.New("acquire authentication session: invalid script status")
		}
		switch status {
		case sessionAcquireMissing:
			return nil, "", _errMissing
		case sessionAcquireBusy:
			busyCount++
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return nil, "", _errBusy
			}
			timer := time.NewTimer(sessionAcquireRetryDelay(remaining))
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, "", ctx.Err()
			case <-timer.C:
			}
			continue
		case sessionAcquireOwned:
		default:
			s.release(ctx, id, owner)
			return nil, "", errors.New("acquire authentication session: unknown script status")
		}
		if len(result) != 2 {
			s.release(ctx, id, owner)
			return nil, "", errors.New("acquire authentication session: invalid script data")
		}
		data, ok := result[1].(string)
		if !ok {
			s.release(ctx, id, owner)
			return nil, "", errors.New("acquire authentication session: invalid script payload")
		}
		var value session
		if err = s.open(key, []byte(data), &value); err != nil {
			s.release(ctx, id, owner)
			return nil, "", err
		}
		if _, err := sessionDeadline(&value, s.nowTime()); err != nil {
			s.release(ctx, id, owner)
			return nil, "", err
		}
		return &value, owner, nil
	}
}

func sessionAcquireRetryDelay(remaining time.Duration) time.Duration {
	delay := sessionAcquireRetryMin + time.Duration(mathrand.Int64N(int64(sessionAcquireRetryMax-sessionAcquireRetryMin+1)))
	if delay > remaining {
		return remaining
	}
	return delay
}
func (s *store) release(requestContext context.Context, id, owner string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(requestContext), time.Second)
	defer cancel()
	// Release is best effort: an unreachable Redis retains the bounded lease until expiry.
	if err := s.db.Eval(ctx, `if redis.call('get',KEYS[1])==ARGV[1] then return redis.call('del',KEYS[1]) end return 0`, []string{s.prefix + "lock:" + id}, owner).Err(); err != nil {
		logs.WarnContext(requestContext, "logtobff.session_lease.release_failed")
	}
}
func (s *store) commit(ctx context.Context, id, owner, next string, value *session, remove bool) error {
	now := s.nowTime()
	if err := validateSessionSchema(value, now); err != nil {
		return err
	}
	key := s.prefix + "s:" + next
	data, err := s.seal(key, value)
	if err != nil {
		return err
	}
	ttl := int64(0)
	if !remove {
		deadline, err := sessionDeadline(value, now)
		if err != nil {
			return err
		}
		ttl = deadline.Sub(now).Milliseconds()
	}
	result, err := s.db.Eval(ctx, `
 if redis.call('get',KEYS[1])~=ARGV[1] or redis.call('exists',KEYS[2])==0 then return 0 end
 if ARGV[5]=='1' then redis.call('del',KEYS[2]) else redis.call('set',KEYS[3],ARGV[2],'PX',ARGV[3]);if KEYS[2]~=KEYS[3] then redis.call('del',KEYS[2]) end end
 redis.call('del',KEYS[1]);return 1`, []string{s.prefix + "lock:" + id, s.prefix + "s:" + id, key}, owner, data, ttl, "", map[bool]string{true: "1", false: "0"}[remove]).Int()
	if err != nil {
		return fmt.Errorf("commit authentication state: %w", err)
	}
	if result != 1 {
		return _errMissing
	}
	return nil
}
