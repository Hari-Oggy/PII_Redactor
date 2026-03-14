package pii

import (
	"testing"
)

func TestTokenMap_StoreAndLookup(t *testing.T) {
	tm, err := NewTokenMap()
	if err != nil {
		t.Fatalf("failed to create token map: %v", err)
	}
	defer tm.Clear()

	token := tm.Store("john@example.com", "email")

	if token == "" {
		t.Fatal("expected non-empty token")
	}

	// Lookup should return the original value.
	original, ok := tm.Lookup(token)
	if !ok {
		t.Fatal("expected token to be found")
	}
	if original != "john@example.com" {
		t.Errorf("expected 'john@example.com', got '%s'", original)
	}
}

func TestTokenMap_DeterministicToken(t *testing.T) {
	tm, err := NewTokenMap()
	if err != nil {
		t.Fatalf("failed to create token map: %v", err)
	}
	defer tm.Clear()

	token1 := tm.Store("john@example.com", "email")
	token2 := tm.Store("john@example.com", "email")

	// Same PII value should produce the same token within a request.
	if token1 != token2 {
		t.Errorf("expected deterministic token, got '%s' and '%s'", token1, token2)
	}
}

func TestTokenMap_DifferentPIIDifferentTokens(t *testing.T) {
	tm, err := NewTokenMap()
	if err != nil {
		t.Fatalf("failed to create token map: %v", err)
	}
	defer tm.Clear()

	token1 := tm.Store("john@example.com", "email")
	token2 := tm.Store("jane@example.com", "email")

	if token1 == token2 {
		t.Error("expected different tokens for different PII values")
	}
}

func TestTokenMap_CleanupReleasesMemory(t *testing.T) {
	tm, err := NewTokenMap()
	if err != nil {
		t.Fatalf("failed to create token map: %v", err)
	}

	tm.Store("test@test.com", "email")
	if tm.Count() != 1 {
		t.Errorf("expected count 1, got %d", tm.Count())
	}

	tm.Clear()

	// After clear, internal maps should be nil.
	if tm.piiToToken != nil {
		t.Error("expected piiToToken to be nil after Clear")
	}
}

func TestTokenMap_InjectionPrevention(t *testing.T) {
	tm, err := NewTokenMap()
	if err != nil {
		t.Fatalf("failed to create token map: %v", err)
	}
	defer tm.Clear()

	// Store a real PII value.
	tm.Store("real-secret@corp.com", "email")

	// A forged token should NOT be found in the map.
	forgedToken := "__PII_email_fakeuuid_fakesig__"
	_, ok := tm.VerifyAndLookup(forgedToken)
	if ok {
		t.Error("forged token should NOT be found in token map")
	}
}
