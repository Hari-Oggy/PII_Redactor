// Package pii — crypto.go provides AES-GCM encryption for PII values
// stored in the TokenMap. If an attacker dumps the Go heap, they get
// ciphertext instead of plaintext PII.
package pii

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
)

// PIICipher provides AES-256-GCM encryption and decryption for PII values
// stored in the in-memory TokenMap. The key is generated once per process
// startup and held only in memory.
type PIICipher struct {
	gcm cipher.AEAD
}

// Global process-level cipher (generated once at startup).
var (
	globalCipher     *PIICipher
	globalCipherOnce sync.Once
	globalCipherErr  error
)

// GetCipher returns the global AES-GCM cipher, creating it on first call.
// The key is generated from crypto/rand and lives only in process memory.
func GetCipher() (*PIICipher, error) {
	globalCipherOnce.Do(func() {
		globalCipher, globalCipherErr = newPIICipher()
	})
	return globalCipher, globalCipherErr
}

// newPIICipher creates a new AES-256-GCM cipher with a random key.
func newPIICipher() (*PIICipher, error) {
	// Generate a random 256-bit key.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate encryption key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	return &PIICipher{gcm: gcm}, nil
}

// Encrypt encrypts a plaintext PII value using AES-256-GCM.
// Returns ciphertext with prepended nonce.
func (c *PIICipher) Encrypt(plaintext string) ([]byte, error) {
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends the ciphertext to the nonce prefix.
	return c.gcm.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

// Decrypt decrypts a ciphertext (with prepended nonce) back to plaintext.
func (c *PIICipher) Decrypt(ciphertext []byte) (string, error) {
	nonceSize := c.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := c.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}
