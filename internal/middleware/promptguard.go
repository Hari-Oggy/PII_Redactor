// Package middleware — promptguard.go detects prompt injection patterns
// in LLM request bodies and blocks or flags them before the request
// leaves the corporate network.
package middleware

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
)

// PromptInjection patterns — common adversarial prompt techniques.
var promptInjectionPatterns = []*regexp.Regexp{
	// Direct instruction override
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|context)`),
	regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)`),
	regexp.MustCompile(`(?i)forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)`),

	// Role-play jailbreaks
	regexp.MustCompile(`(?i)you\s+are\s+now\s+(DAN|evil|unrestricted|unfiltered|jailbroken)`),
	regexp.MustCompile(`(?i)pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(hacker|evil|malicious|unrestricted)`),
	regexp.MustCompile(`(?i)act\s+as\s+(if\s+)?(you\s+(have|had)\s+)?(no|zero)\s+(restrictions?|limitations?|filters?|rules?)`),

	// System prompt extraction
	regexp.MustCompile(`(?i)(reveal|show|print|display|output|repeat)\s+(your|the|system)\s+(system\s+)?(prompt|instructions?|rules?|configuration)`),
	regexp.MustCompile(`(?i)what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?|rules?)`),

	// Encoding-based bypass
	regexp.MustCompile(`(?i)(base64|rot13|hex)\s*(encode|decode|encrypt|decrypt)\s+(the\s+)?(following|this)`),

	// Developer/debug mode
	regexp.MustCompile(`(?i)(enter|enable|activate|switch\s+to)\s+(developer|debug|admin|maintenance|test)\s+mode`),

	// Delimiter injection
	regexp.MustCompile(`(?i)\[SYSTEM\]|\[INST\]|<<SYS>>|<\|im_start\|>|<\|system\|>`),
}

// PromptGuardConfig holds configuration for the prompt guard middleware.
type PromptGuardConfig struct {
	Enabled     bool   // Whether to enable prompt injection detection.
	Mode        string // "block" to reject, "flag" to log and pass through.
	CustomTerms []string
}

// PromptGuard returns middleware that scans request bodies for prompt
// injection patterns. If detected, the request is either blocked (403)
// or flagged in the logs, depending on configuration.
func PromptGuard(mode string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body == nil || r.ContentLength == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Read the body (we'll restore it after scanning).
			body, err := io.ReadAll(r.Body)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			// Scan for prompt injection patterns.
			bodyStr := string(body)
			requestID := r.Header.Get(CorrelationIDHeader)

			for _, pattern := range promptInjectionPatterns {
				if loc := pattern.FindStringIndex(bodyStr); loc != nil {
					matched := bodyStr[loc[0]:loc[1]]

					if strings.ToLower(mode) == "block" {
						log.Printf("[%s] PROMPT INJECTION BLOCKED: pattern=%q match=%q",
							requestID, pattern.String(), matched)
						RecordPromptInjection("blocked")
						http.Error(w,
							`{"error":"request blocked: potential prompt injection detected"}`,
							http.StatusForbidden)
						return
					}

					// Flag mode: log warning but allow the request through.
					log.Printf("[%s] PROMPT INJECTION FLAGGED: pattern=%q match=%q",
						requestID, pattern.String(), matched)
					RecordPromptInjection("flagged")
					// Add a header so downstream handlers know this was flagged.
					r.Header.Set("X-Prompt-Injection", "flagged")
					break // One flag is enough.
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RecordPromptInjection is a stub for Prometheus metric recording.
// Will be wired to the metrics system in Phase 4.
func RecordPromptInjection(action string) {
	// TODO: Increment Prometheus counter for prompt_injection_total{action="blocked|flagged"}
}
