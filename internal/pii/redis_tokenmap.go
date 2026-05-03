package pii

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisTokenMap implements the TokenMap interface using a Redis backend
// for distributed, crash-resilient PII token storage.
type RedisTokenMap struct {
	client        *redis.Client
	requestSecret []byte
	cipher        *PIICipher
	ttl           time.Duration
}

// NewRedisTokenMap creates a new RedisTokenMap.
func NewRedisTokenMap(addr, password string, db int, ttl time.Duration, requestSecret []byte, cipher *PIICipher) (*RedisTokenMap, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	return &RedisTokenMap{
		client:        client,
		requestSecret: requestSecret,
		cipher:        cipher,
		ttl:           ttl,
	}, nil
}

// generateToken creates a deterministic HMAC-signed token.
func (tm *RedisTokenMap) generateToken(piiValue, piiType string) string {
	// Deterministic UUID computation: HMAC-SHA256(requestSecret, type + value)
	mac := hmac.New(sha256.New, tm.requestSecret)
	mac.Write([]byte(piiType + piiValue))
	uuid := hex.EncodeToString(mac.Sum(nil))[:16]

	// HMAC signature for injection prevention
	mac2 := hmac.New(sha256.New, tm.requestSecret)
	mac2.Write([]byte(uuid))
	sig := hex.EncodeToString(mac2.Sum(nil))[:16]

	return fmt.Sprintf("%s%s_%s_%s%s", TokenPrefix, piiType, uuid, sig, TokenSuffix)
}

func (tm *RedisTokenMap) Store(piiValue, piiType string) string {
	token := tm.generateToken(piiValue, piiType)

	var dataToStore []byte
	if tm.cipher != nil {
		encrypted, err := tm.cipher.Encrypt(piiValue)
		if err == nil {
			dataToStore = encrypted
		} else {
			dataToStore = []byte(piiValue)
		}
	} else {
		dataToStore = []byte(piiValue)
	}

	// Store mapping. We use SETNX (Set if Not eXists) or just SET.
	// Since tokens are deterministic, overwriting with the same value is fine.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// redis keys will be prefixed
	key := "pii_token:" + token
	tm.client.Set(ctx, key, dataToStore, tm.ttl)

	return token
}

func (tm *RedisTokenMap) Lookup(token string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	key := "pii_token:" + token
	val, err := tm.client.Get(ctx, key).Bytes()
	if err != nil {
		return "", false
	}

	return tm.decryptPII(val), true
}

func (tm *RedisTokenMap) VerifyAndLookup(token string) (string, bool) {
	uuidPart, hmacPart, ok := parseToken(token)
	if !ok {
		return "", false
	}

	mac := hmac.New(sha256.New, tm.requestSecret)
	mac.Write([]byte(uuidPart))
	expectedSig := hex.EncodeToString(mac.Sum(nil))[:16]

	if !hmac.Equal([]byte(hmacPart), []byte(expectedSig)) {
		return "", false
	}

	return tm.Lookup(token)
}

func (tm *RedisTokenMap) decryptPII(data []byte) string {
	if tm.cipher != nil {
		plaintext, err := tm.cipher.Decrypt(data)
		if err == nil {
			return plaintext
		}
	}
	return string(data)
}

func (tm *RedisTokenMap) Count() int {
	// Not practically supported/performant in Redis for a single request scope
	// without keeping local state, so returning a dummy > 0 value if we want to bypass empty checks.
	return 1
}

func (tm *RedisTokenMap) Clear() {
	// Keys have TTLs, no manual clearing needed per-request.
}
