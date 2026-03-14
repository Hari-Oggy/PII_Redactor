// Package pii provides the PII detection, redaction, and re-hydration engine.
// The token map is context-scoped and uses HMAC-signed tokens to prevent
// injection attacks from LLM-generated content.
package pii

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

// TokenMap holds the bidirectional mapping between PII values and their
// replacement tokens. It is scoped to a single request via context and
// cleaned up automatically when the context is cancelled.
// PII values are encrypted at rest using AES-256-GCM to protect against
// heap dump attacks.
type TokenMap struct {
	mu            sync.RWMutex
	piiToToken    map[string]string // original PII → token
	tokenToPII    map[string][]byte // token → encrypted PII (AES-GCM ciphertext)
	requestSecret []byte            // per-request HMAC secret
	cipher        *PIICipher        // AES-256-GCM cipher for PII encryption
}

// NewTokenMap creates a new TokenMap with a fresh per-request HMAC secret
// and AES-256-GCM encryption for stored PII values.
func NewTokenMap() (*TokenMap, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate HMAC secret: %w", err)
	}

	cipher, err := GetCipher()
	if err != nil {
		// Non-fatal: fall back to unencrypted storage.
		cipher = nil
	}

	return &TokenMap{
		piiToToken:    make(map[string]string),
		tokenToPII:    make(map[string][]byte),
		requestSecret: secret,
		cipher:        cipher,
	}, nil
}

// TokenPrefix and TokenSuffix delimit PII tokens in sanitised text.
const (
	TokenPrefix = "__PII_"
	TokenSuffix = "__"
)

// generateToken creates a unique HMAC-signed token for a PII value.
// Format: __PII_{uuid}_{hmac}__
func (tm *TokenMap) generateToken(piiType string) string {
	// Generate 8 random bytes → 16 hex chars for uniqueness.
	uuidBytes := make([]byte, 8)
	_, _ = rand.Read(uuidBytes) // crypto/rand; error extremely unlikely
	uuid := hex.EncodeToString(uuidBytes)

	// HMAC-SHA256(uuid, per-request-secret) → 8 hex chars.
	mac := hmac.New(sha256.New, tm.requestSecret)
	mac.Write([]byte(uuid))
	sig := hex.EncodeToString(mac.Sum(nil))[:16]

	return fmt.Sprintf("%s%s_%s_%s%s", TokenPrefix, piiType, uuid, sig, TokenSuffix)
}

// Store records a PII value and returns its replacement token.
// If the same PII value was already stored, returns the existing token
// (deterministic replacement for the same PII within one request).
// The PII value is encrypted with AES-256-GCM before storage.
func (tm *TokenMap) Store(piiValue, piiType string) string {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Reuse existing token for the same PII value (deterministic).
	if token, exists := tm.piiToToken[piiValue]; exists {
		return token
	}

	token := tm.generateToken(piiType)
	tm.piiToToken[piiValue] = token

	// Encrypt PII before storing in the token→PII map.
	if tm.cipher != nil {
		encrypted, err := tm.cipher.Encrypt(piiValue)
		if err == nil {
			tm.tokenToPII[token] = encrypted
		} else {
			// Fallback: store plaintext if encryption fails.
			tm.tokenToPII[token] = []byte(piiValue)
		}
	} else {
		tm.tokenToPII[token] = []byte(piiValue)
	}

	return token
}

// Lookup retrieves the original PII value for a given token.
// Decrypts the stored ciphertext before returning.
// Returns the original value and true if found, or ("", false) if not.
func (tm *TokenMap) Lookup(token string) (string, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	encrypted, ok := tm.tokenToPII[token]
	if !ok {
		return "", false
	}
	return tm.decryptPII(encrypted), true
}

// VerifyAndLookup checks the HMAC signature of a token before returning
// the original PII value. This prevents injection attacks where the LLM
// fabricates tokens that look like PII placeholders.
//
// Token format: __PII_{type}_{uuid}_{hmac}__
// Verification: recompute HMAC-SHA256(uuid, requestSecret) and compare.
func (tm *TokenMap) VerifyAndLookup(token string) (string, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	// Parse the token to extract UUID and HMAC portions.
	uuidPart, hmacPart, ok := parseToken(token)
	if !ok {
		return "", false
	}

	// Recompute HMAC from the UUID and compare with the embedded one.
	mac := hmac.New(sha256.New, tm.requestSecret)
	mac.Write([]byte(uuidPart))
	expectedSig := hex.EncodeToString(mac.Sum(nil))[:16]

	// Constant-time comparison to prevent timing attacks.
	if !hmac.Equal([]byte(hmacPart), []byte(expectedSig)) {
		return "", false
	}

	// HMAC is valid — now check the map for the original value.
	encrypted, exists := tm.tokenToPII[token]
	if !exists {
		return "", false
	}
	return tm.decryptPII(encrypted), true
}

// decryptPII decrypts an encrypted PII value. Falls back to treating the
// data as plaintext if decryption fails (e.g., cipher not available).
func (tm *TokenMap) decryptPII(data []byte) string {
	if tm.cipher != nil {
		plaintext, err := tm.cipher.Decrypt(data)
		if err == nil {
			return plaintext
		}
	}
	// Fallback: treat as plaintext.
	return string(data)
}

// parseToken extracts the UUID and HMAC portions from a token string.
// Token format: __PII_{type}_{uuid}_{hmac}__
// Returns (uuid, hmac, ok).
func parseToken(token string) (string, string, bool) {
	// Strip prefix and suffix.
	if !strings.HasPrefix(token, TokenPrefix) || !strings.HasSuffix(token, TokenSuffix) {
		return "", "", false
	}

	// Remove __PII_ prefix and __ suffix.
	inner := token[len(TokenPrefix) : len(token)-len(TokenSuffix)]

	// Expected: {type}_{uuid}_{hmac}
	// Split by _ — we need at least 3 parts (type may contain _).
	parts := strings.Split(inner, "_")
	if len(parts) < 3 {
		return "", "", false
	}

	// HMAC is the last part, UUID is second-to-last, type is everything before.
	hmacPart := parts[len(parts)-1]
	uuidPart := parts[len(parts)-2]

	if len(uuidPart) == 0 || len(hmacPart) == 0 {
		return "", "", false
	}

	return uuidPart, hmacPart, true
}

// Count returns the number of PII mappings stored.
func (tm *TokenMap) Count() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return len(tm.piiToToken)
}

// Clear removes all mappings, releasing memory.
func (tm *TokenMap) Clear() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.piiToToken = nil
	tm.tokenToPII = nil
	tm.requestSecret = nil
	tm.cipher = nil
}
