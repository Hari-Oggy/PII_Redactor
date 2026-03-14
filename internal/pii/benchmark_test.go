package pii

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// BenchmarkRegexDetector_ShortText benchmarks PII detection on a short string.
func BenchmarkRegexDetector_ShortText(b *testing.B) {
	d := NewRegexDetector()
	text := "Contact john@acme.com for SSN 123-45-6789"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(text, 50*time.Millisecond)
	}
}

// BenchmarkRegexDetector_LongText benchmarks PII detection on a 10KB body.
func BenchmarkRegexDetector_LongText(b *testing.B) {
	d := NewRegexDetector()
	// Build a 10KB text with scattered PII.
	var sb strings.Builder
	for i := 0; i < 100; i++ {
		sb.WriteString("This is a normal paragraph of text that doesn't contain any PII. ")
	}
	sb.WriteString("Hidden email: target@secret.com and SSN: 999-88-7777. ")
	for i := 0; i < 100; i++ {
		sb.WriteString("More harmless text to increase the body size for realistic testing. ")
	}
	text := sb.String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(text, 50*time.Millisecond)
	}
}

// BenchmarkPipeline_Detect benchmarks the full pipeline with multiple detectors.
func BenchmarkPipeline_Detect(b *testing.B) {
	regex := NewRegexDetector()
	blocklist := NewBlocklistDetector([]string{"CONFIDENTIAL", "SECRET", "INTERNAL"})
	allowlist := NewAllowlist([]string{"safe@example.com"})
	pipeline := NewPipeline([]Detector{regex, blocklist}, 0.8, allowlist, 50_000_000)

	text := "Email john@acme.com, SSN 123-45-6789, this is CONFIDENTIAL"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pipeline.Detect(text)
	}
}

// BenchmarkTokenMap_StoreAndLookup benchmarks token map operations.
func BenchmarkTokenMap_StoreAndLookup(b *testing.B) {
	tm, _ := NewTokenMap()
	defer tm.Clear()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token := tm.Store(fmt.Sprintf("user%d@test.com", i), "email")
		tm.Lookup(token)
	}
}

// BenchmarkTokenMap_VerifyAndLookup benchmarks HMAC-verified lookups.
func BenchmarkTokenMap_VerifyAndLookup(b *testing.B) {
	tm, _ := NewTokenMap()
	defer tm.Clear()

	// Pre-store tokens.
	tokens := make([]string, 100)
	for i := 0; i < 100; i++ {
		tokens[i] = tm.Store(fmt.Sprintf("user%d@test.com", i), "email")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tm.VerifyAndLookup(tokens[i%100])
	}
}

// BenchmarkRedactAndRehydrate benchmarks the full redact → rehydrate cycle.
func BenchmarkRedactAndRehydrate(b *testing.B) {
	text := "Email: alice@corp.com, SSN: 111-22-3333, Phone: (555) 999-0000"
	detector := NewRegexDetector()
	redactor := NewRedactor()
	rehydrator := NewRehydrator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tm, _ := NewTokenMap()
		matches := detector.Detect(text, 50*time.Millisecond)
		redacted, _ := redactor.Redact(text, matches, tm)
		rehydrator.Rehydrate(redacted, tm)
		tm.Clear()
	}
}

// BenchmarkLuhnCheck benchmarks the Luhn validation algorithm.
func BenchmarkLuhnCheck(b *testing.B) {
	// Valid Visa test number.
	cardNumber := "4111 1111 1111 1111"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		luhnCheck(cardNumber)
	}
}
