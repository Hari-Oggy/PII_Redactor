package pii

import (
	"strings"
	"testing"
	"time"
)

func TestRegexDetector_Email(t *testing.T) {
	d := NewRegexDetector()
	matches := d.Detect("Contact me at john.doe@acme.com for details", 50*time.Millisecond)

	if len(matches) == 0 {
		t.Fatal("expected email match, got none")
	}

	found := false
	for _, m := range matches {
		if m.Type == "email" && m.Value == "john.doe@acme.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected email 'john.doe@acme.com', matches: %+v", matches)
	}
}

func TestRegexDetector_SSN(t *testing.T) {
	d := NewRegexDetector()
	matches := d.Detect("My SSN is 123-45-6789", 50*time.Millisecond)

	if len(matches) == 0 {
		t.Fatal("expected SSN match, got none")
	}

	found := false
	for _, m := range matches {
		if m.Type == "ssn" && m.Value == "123-45-6789" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected SSN '123-45-6789', matches: %+v", matches)
	}
}

func TestRegexDetector_AWSKey(t *testing.T) {
	d := NewRegexDetector()
	matches := d.Detect("key is AKIAIOSFODNN7EXAMPLE", 50*time.Millisecond)

	found := false
	for _, m := range matches {
		if m.Type == "api_key" && strings.Contains(m.Value, "AKIAIOSFODNN7EXAMPLE") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected AWS key match, matches: %+v", matches)
	}
}

func TestRegexDetector_Phone(t *testing.T) {
	d := NewRegexDetector()
	matches := d.Detect("Call me at (555) 123-4567", 50*time.Millisecond)

	found := false
	for _, m := range matches {
		if m.Type == "phone" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected phone match, matches: %+v", matches)
	}
}

func TestRegexDetector_NoFalsePositiveOnPlainText(t *testing.T) {
	d := NewRegexDetector()
	matches := d.Detect("Hello, how are you today?", 50*time.Millisecond)

	// Should not match any PII in plain greeting.
	for _, m := range matches {
		if m.Confidence >= 0.9 {
			t.Errorf("unexpected high-confidence match in plain text: %+v", m)
		}
	}
}

func TestRegexDetector_Timeout(t *testing.T) {
	d := NewRegexDetector()
	// Use extremely short timeout — should still return without hanging.
	matches := d.Detect("test@example.com", 1*time.Nanosecond)
	// We just verify it doesn't hang; matches may or may not be found.
	_ = matches
}
