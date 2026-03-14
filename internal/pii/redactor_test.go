package pii

import (
	"testing"
	"time"

	"github.com/enterprise/pii-gateway/pkg/models"
)

func TestRedactAndRehydrate_RoundTrip(t *testing.T) {
	tm, err := NewTokenMap()
	if err != nil {
		t.Fatalf("failed to create token map: %v", err)
	}
	defer tm.Clear()

	original := "My email is john@acme.com and SSN is 123-45-6789"

	// Detect PII.
	detector := NewRegexDetector()
	matches := detector.Detect(original, 50*time.Millisecond)

	if len(matches) < 2 {
		t.Fatalf("expected at least 2 matches (email + SSN), got %d", len(matches))
	}

	// Redact.
	redactor := NewRedactor()
	redacted, spans := redactor.Redact(original, matches, tm)

	t.Logf("Original:  %s", original)
	t.Logf("Redacted:  %s", redacted)
	t.Logf("Spans:     %d", len(spans))

	// Redacted text should NOT contain the original PII.
	if containsAny(redacted, []string{"john@acme.com", "123-45-6789"}) {
		t.Error("redacted text still contains PII")
	}

	// Redacted text should contain PII tokens.
	if !containsAny(redacted, []string{TokenPrefix}) {
		t.Error("redacted text does not contain PII tokens")
	}

	// Re-hydrate.
	rehydrator := NewRehydrator()
	restored := rehydrator.Rehydrate(redacted, tm)

	t.Logf("Restored:  %s", restored)

	// Restored text should match original.
	if restored != original {
		t.Errorf("round-trip failed:\n  original: %s\n  restored: %s", original, restored)
	}
}

func TestRedact_PreservesNonPIIText(t *testing.T) {
	tm, err := NewTokenMap()
	if err != nil {
		t.Fatalf("failed to create token map: %v", err)
	}
	defer tm.Clear()

	original := "Hello, how are you today?"

	matches := []models.PIIMatch{} // no PII
	redactor := NewRedactor()
	redacted, spans := redactor.Redact(original, matches, tm)

	if redacted != original {
		t.Errorf("expected unchanged text, got '%s'", redacted)
	}
	if len(spans) != 0 {
		t.Errorf("expected 0 spans, got %d", len(spans))
	}
}

func containsAny(text string, substrs []string) bool {
	for _, s := range substrs {
		if len(s) > 0 && contains(text, s) {
			return true
		}
	}
	return false
}

func contains(text, substr string) bool {
	return len(text) >= len(substr) && searchString(text, substr)
}

func searchString(text, substr string) bool {
	for i := 0; i <= len(text)-len(substr); i++ {
		if text[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
