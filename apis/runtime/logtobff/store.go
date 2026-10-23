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
	"time"

	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/redis/go-redis/v9"
)

var _errMissing = errors.New("session missing")
var _errBusy = errors.New("session busy")

// Redis owns short-lived authentication capabilities only. Every value is encrypted;
// the key prefix is authenticated too, preventing transaction/session substitution.
type store struct {
	prefix  string
	db      *redis.Client
	box     cipher.AEAD
	entropy io.Reader
}
type session struct {
	SDK          map[string]string `json:"sdk"`
	Subject      string            `json:"subject"`
	Organization string            `json:"organization"`
	Revision     string            `json:"revision"`
	CSRF         string            `json:"csrf"`
	Until        time.Time         `json:"until"`
	Profile      *profile          `json:"profile,omitempty"`
	ProfileUntil time.Time         `json:"profile_until,omitempty"`
}
type transaction struct {
	SDK      map[string]string `json:"sdk"`
	Nonce    string            `json:"nonce"`
	State    string            `json:"state"`
	ReturnTo string            `json:"return_to"`
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
	return &store{db: redis.NewClient(&redis.Options{Addr: address, Password: password, DialTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second, MaxRetries: -1, PoolSize: 8, MaxActiveConns: 8, ContextTimeoutEnabled: true, PoolTimeout: time.Second}), box: box, prefix: prefix, entropy: rand.Reader}, nil
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
	return id, s.db.Eval(ctx, `redis.call('set',KEYS[1],ARGV[1],'PX',ARGV[2]);redis.call('del',KEYS[2]);return 1`, []string{key, s.prefix + "s:" + previous}, data, time.Until(value.Until).Milliseconds()).Err()
}

// A fixed 30s lease outlives the entire 20s request budget. All commits are fenced
// by lease ownership and source existence; a late writer cannot revive logout.
func (s *store) acquire(ctx context.Context, id string) (*session, string, error) {
	if !_opaquePattern.MatchString(id) {
		return nil, "", _errMissing
	}
	owner, err := s.opaque()
	if err != nil {
		return nil, "", err
	}
	lock := s.prefix + "lock:" + id
	// Remote identity checks share the 20s authentication budget with this wait.
	deadline := time.Now().Add(_authenticationTimeout)
	for {
		ok, err := s.db.SetNX(ctx, lock, owner, 30*time.Second).Result()
		if err != nil {
			return nil, "", err
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			return nil, "", _errBusy
		}
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	key := s.prefix + "s:" + id
	data, err := s.db.Get(ctx, key).Bytes()
	if err != nil {
		s.release(ctx, id, owner)
		if errors.Is(err, redis.Nil) {
			err = _errMissing
		}
		return nil, "", err
	}
	var value session
	if err = s.open(key, data, &value); err != nil {
		s.release(ctx, id, owner)
		return nil, "", err
	}
	if !time.Now().Before(value.Until) {
		s.release(ctx, id, owner)
		return nil, "", _errMissing
	}
	return &value, owner, nil
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
	key := s.prefix + "s:" + next
	data, err := s.seal(key, value)
	if err != nil {
		return err
	}
	ttl := time.Until(value.Until).Milliseconds()
	if ttl <= 0 {
		return _errMissing
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
