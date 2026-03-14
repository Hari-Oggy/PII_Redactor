package pii

import (
	"regexp"
	"time"

	"github.com/enterprise/pii-gateway/pkg/models"
)

// RegexDetector uses compiled regular expressions to detect structured PII
// such as emails, SSNs, credit card numbers, and phone numbers.
// Each regex execution is guarded by a timeout to prevent ReDoS attacks.
type RegexDetector struct {
	patterns []regexPattern
}

type regexPattern struct {
	name       string
	re         *regexp.Regexp
	piiType    string
	confidence float64
}

// NewRegexDetector creates a detector with built-in PII patterns.
func NewRegexDetector() *RegexDetector {
	return &RegexDetector{
		patterns: defaultPatterns(),
	}
}

func defaultPatterns() []regexPattern {
	return []regexPattern{
		{
			name:       "email",
			re:         regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			piiType:    "email",
			confidence: 0.95,
		},
		{
			name:       "ssn",
			re:         regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			piiType:    "ssn",
			confidence: 0.98,
		},
		{
			name: "credit_card",
			// Stricter pattern: matches Visa, MasterCard, Amex, Discover formats.
			// Allows spaces or dashes as separators. Luhn-validated post-match.
			re:         regexp.MustCompile(`\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,4}\b`),
			piiType:    "credit_card",
			confidence: 0.90,
		},
		{
			name:       "phone_us",
			re:         regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
			piiType:    "phone",
			confidence: 0.85,
		},
		{
			name:       "phone_intl",
			re:         regexp.MustCompile(`\b\+\d{1,3}[-.\s]?\d{4,14}\b`),
			piiType:    "phone",
			confidence: 0.80,
		},
		{
			name:       "ip_address",
			re:         regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			piiType:    "ip_address",
			confidence: 0.75,
		},
		{
			name:       "api_key_generic",
			re:         regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{20,})["']?`),
			piiType:    "api_key",
			confidence: 0.90,
		},
		{
			name:       "aws_key",
			re:         regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			piiType:    "api_key",
			confidence: 0.98,
		},
	}
}

// Name returns the detector name.
func (d *RegexDetector) Name() string {
	return "regex"
}

// Detect scans text using all regex patterns within the given timeout.
func (d *RegexDetector) Detect(text string, timeout time.Duration) []models.PIIMatch {
	// Use a channel to safely return results (avoids data race on shared slice).
	resultCh := make(chan []models.PIIMatch, 1)

	go func() {
		var matches []models.PIIMatch
		for _, p := range d.patterns {
			locs := p.re.FindAllStringIndex(text, -1)
			for _, loc := range locs {
				value := text[loc[0]:loc[1]]

				// Credit card matches require Luhn validation.
				if p.piiType == "credit_card" && !luhnCheck(value) {
					continue
				}

				matches = append(matches, models.PIIMatch{
					Type:         p.piiType,
					Start:        loc[0],
					End:          loc[1],
					Value:        value,
					Confidence:   p.confidence,
					DetectorName: "regex:" + p.name,
				})
			}
		}
		resultCh <- matches
	}()

	// ReDoS guard — timeout if regex takes too long.
	select {
	case matches := <-resultCh:
		return matches
	case <-time.After(timeout):
		// Timeout — return empty (goroutine result is no longer safe to read).
		return nil
	}
}

// luhnCheck validates a number string using the Luhn algorithm.
// Strips non-digit characters (spaces, dashes) before validation.
func luhnCheck(s string) bool {
	// Extract digits only.
	var digits []int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}

	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	// Luhn algorithm: from right to left, double every second digit.
	sum := 0
	nDigits := len(digits)
	parity := nDigits % 2

	for i := 0; i < nDigits; i++ {
		d := digits[i]
		if i%2 == parity {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}

	return sum%10 == 0
}
