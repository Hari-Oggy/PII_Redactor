package pii

import (
	"testing"
	"time"
)

// FuzzRegexDetector tests the regex detector with random inputs to find
// panics, hangs, or other issues.
func FuzzRegexDetector(f *testing.F) {
	// Seed corpus with known PII patterns.
	f.Add("Contact me at john@example.com")
	f.Add("SSN: 123-45-6789")
	f.Add("Call (555) 123-4567")
	f.Add("AKIAIOSFODNN7EXAMPLE")
	f.Add("api_key = sk-abc123def456ghi789jkl0")
	f.Add("Just plain text with no PII")
	f.Add("")
	f.Add("a]@b.c") // edge case for email regex
	f.Add("000-00-0000")
	f.Add("+1-555-000-0000")

	d := NewRegexDetector()

	f.Fuzz(func(t *testing.T, input string) {
		// Should never panic or hang (50ms timeout protects against hang).
		matches := d.Detect(input, 50*time.Millisecond)
		// Verify all matches have valid fields.
		for _, m := range matches {
			if m.Start < 0 || m.End < 0 || m.Start > m.End {
				t.Errorf("invalid span: start=%d end=%d", m.Start, m.End)
			}
			if m.End > len(input) {
				t.Errorf("span end %d exceeds input length %d", m.End, len(input))
			}
			if m.Type == "" {
				t.Error("match has empty type")
			}
			if m.Confidence < 0 || m.Confidence > 1.0 {
				t.Errorf("confidence %f out of range", m.Confidence)
			}
		}
	})
}

// FuzzTokenMapStoreAndLookup tests that Store → Lookup always round-trips.
func FuzzTokenMapStoreAndLookup(f *testing.F) {
	f.Add("john@example.com", "email")
	f.Add("123-45-6789", "ssn")
	f.Add("(555) 123-4567", "phone")
	f.Add("", "empty")
	f.Add("special chars: !@#$%^&*()", "text")

	f.Fuzz(func(t *testing.T, value, piiType string) {
		tm, err := NewTokenMap()
		if err != nil {
			t.Fatalf("NewTokenMap: %v", err)
		}
		defer tm.Clear()

		token := tm.Store(value, piiType)

		if token == "" {
			t.Fatal("got empty token")
		}

		// Lookup should return the original value.
		got, ok := tm.Lookup(token)
		if !ok {
			t.Fatal("Lookup failed for stored token")
		}
		if got != value {
			t.Errorf("Lookup returned %q, want %q", got, value)
		}

		// VerifyAndLookup should also succeed.
		got2, ok2 := tm.VerifyAndLookup(token)
		if !ok2 {
			t.Fatal("VerifyAndLookup failed for stored token")
		}
		if got2 != value {
			t.Errorf("VerifyAndLookup returned %q, want %q", got2, value)
		}
	})
}

// FuzzRehydrator tests that redact → rehydrate always round-trips.
func FuzzRehydrator(f *testing.F) {
	f.Add("My email is john@example.com")
	f.Add("SSN 123-45-6789 is mine")
	f.Add("No PII here at all")
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 10000 {
			return // skip very long inputs
		}

		tm, err := NewTokenMap()
		if err != nil {
			t.Fatalf("NewTokenMap: %v", err)
		}
		defer tm.Clear()

		detector := NewRegexDetector()
		matches := detector.Detect(input, 50*time.Millisecond)

		redactor := NewRedactor()
		redacted, _ := redactor.Redact(input, matches, tm)

		rehydrator := NewRehydrator()
		restored := rehydrator.Rehydrate(redacted, tm)

		// Round-trip should produce the original input.
		if restored != input {
			t.Errorf("round-trip failed:\n  input:    %q\n  redacted: %q\n  restored: %q",
				input, redacted, restored)
		}
	})
}
