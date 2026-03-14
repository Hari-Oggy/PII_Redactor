package pii

import (
	"regexp"
	"strings"
)

// tokenRegex matches PII tokens of the format __PII_{type}_{uuid}_{hmac}__
var tokenRegex = regexp.MustCompile(`__PII_[a-zA-Z0-9_]+__`)

// Rehydrator restores HMAC-verified PII tokens in LLM responses
// back to their original values. Only tokens that pass HMAC verification
// are replaced — fabricated tokens are left as-is (injection prevention).
type Rehydrator struct{}

// NewRehydrator creates a new Rehydrator.
func NewRehydrator() *Rehydrator {
	return &Rehydrator{}
}

// Rehydrate scans text for PII tokens and replaces only HMAC-verified
// ones with their original values from the TokenMap.
// Tokens that fail HMAC verification (e.g., LLM-fabricated tokens)
// are left as-is, preventing injection attacks.
func (r *Rehydrator) Rehydrate(text string, tm *TokenMap) string {
	if tm.Count() == 0 {
		return text
	}

	// Find all token-shaped strings in the text.
	result := tokenRegex.ReplaceAllStringFunc(text, func(match string) string {
		// Only replace if the token passes HMAC verification.
		if original, ok := tm.VerifyAndLookup(match); ok {
			return original
		}
		// Token failed verification — leave it as-is.
		// This is the injection prevention: LLM-fabricated tokens
		// won't have a valid HMAC and are not replaced.
		return match
	})

	// Also handle any exact tokens that might not match the regex
	// (defensive — iterate verified tokens only).
	tm.mu.RLock()
	tokens := make([]string, 0, len(tm.tokenToPII))
	for token := range tm.tokenToPII {
		tokens = append(tokens, token)
	}
	tm.mu.RUnlock()

	for _, token := range tokens {
		if strings.Contains(result, token) {
			if _, _, ok := parseToken(token); ok {
				if original, found := tm.Lookup(token); found {
					result = strings.ReplaceAll(result, token, original)
				}
			}
		}
	}

	return result
}

