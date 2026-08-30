package sessiongateway

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	errSessionNotFound  = errors.New("session not found")
	errSessionCorrupt   = errors.New("session payload is invalid")
	errSessionCollision = errors.New("session identifier collision")
)

const sessionKeyPrefix = "pug:dashboard:session:"

type sessionRecord struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	CustomerID       string `json:"customer_id"`
	CSRFToken        string `json:"csrf_token"`
	AccessExpiresAt  int64  `json:"access_expires_at"`
	SessionExpiresAt int64  `json:"session_expires_at"`
	Demo             bool   `json:"demo"`
}

type sessionStore interface {
	Create(context.Context, string, sessionRecord, time.Duration) error
	Get(context.Context, string) (sessionRecord, error)
	Put(context.Context, string, sessionRecord, time.Duration) error
	Delete(context.Context, string) error
	TryRefreshLock(context.Context, string, string, time.Duration) (bool, error)
	ReleaseRefreshLock(context.Context, string, string) error
	Ping(context.Context) error
}

type redisSessionStore struct {
	client *redis.Client
	aead   cipher.AEAD
}

func newRedisSessionStore(client *redis.Client, key []byte) (*redisSessionStore, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize session cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize session AEAD: %w", err)
	}
	return &redisSessionStore{client: client, aead: aead}, nil
}

func (s *redisSessionStore) Create(ctx context.Context, id string, record sessionRecord, ttl time.Duration) error {
	payload, err := s.seal(id, record)
	if err != nil {
		return err
	}
	created, err := s.client.SetNX(ctx, redisSessionKey(id), payload, ttl).Result()
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	if !created {
		return errSessionCollision
	}
	return nil
}

func (s *redisSessionStore) Get(ctx context.Context, id string) (sessionRecord, error) {
	payload, err := s.client.Get(ctx, redisSessionKey(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return sessionRecord{}, errSessionNotFound
	}
	if err != nil {
		return sessionRecord{}, fmt.Errorf("read session: %w", err)
	}
	record, err := s.open(id, payload)
	if err != nil {
		return sessionRecord{}, errors.Join(errSessionCorrupt, err)
	}
	return record, nil
}

func (s *redisSessionStore) Put(ctx context.Context, id string, record sessionRecord, ttl time.Duration) error {
	payload, err := s.seal(id, record)
	if err != nil {
		return err
	}
	if err := s.client.Set(ctx, redisSessionKey(id), payload, ttl).Err(); err != nil {
		return fmt.Errorf("update session: %w", err)
	}
	return nil
}

func (s *redisSessionStore) Delete(ctx context.Context, id string) error {
	if err := s.client.Del(ctx, redisSessionKey(id)).Err(); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *redisSessionStore) TryRefreshLock(
	ctx context.Context,
	id string,
	owner string,
	ttl time.Duration,
) (bool, error) {
	locked, err := s.client.SetNX(ctx, redisRefreshLockKey(id), owner, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("acquire session refresh lock: %w", err)
	}
	return locked, nil
}

var releaseRefreshLockScript = redis.NewScript(`
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("del", KEYS[1])
end
return 0
`)

func (s *redisSessionStore) ReleaseRefreshLock(ctx context.Context, id, owner string) error {
	if err := releaseRefreshLockScript.Run(ctx, s.client, []string{redisRefreshLockKey(id)}, owner).Err(); err != nil {
		return fmt.Errorf("release session refresh lock: %w", err)
	}
	return nil
}

func (s *redisSessionStore) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

func (s *redisSessionStore) seal(id string, record sessionRecord) ([]byte, error) {
	// #nosec G117 -- this plaintext exists only in process memory and is immediately sealed with AES-GCM.
	plain, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("marshal session: %w", err)
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate session nonce: %w", err)
	}
	return s.aead.Seal(nonce, nonce, plain, []byte(redisSessionKey(id))), nil
}

func (s *redisSessionStore) open(id string, payload []byte) (sessionRecord, error) {
	if len(payload) < s.aead.NonceSize() {
		return sessionRecord{}, errors.New("ciphertext is too short")
	}
	nonce, ciphertext := payload[:s.aead.NonceSize()], payload[s.aead.NonceSize():]
	plain, err := s.aead.Open(nil, nonce, ciphertext, []byte(redisSessionKey(id)))
	if err != nil {
		return sessionRecord{}, errors.New("decrypt session payload")
	}
	var record sessionRecord
	if err := json.Unmarshal(plain, &record); err != nil {
		return sessionRecord{}, errors.New("decode session payload")
	}
	return record, nil
}

func redisSessionKey(id string) string {
	sum := sha256.Sum256([]byte(id))
	return sessionKeyPrefix + hex.EncodeToString(sum[:])
}

func redisRefreshLockKey(id string) string {
	return redisSessionKey(id) + ":refresh"
}
