// Real demo -- hits the actual Gemini API with PII redaction.
//
// Reads API key from api.key.txt or GEMINI_API_KEY env var.
// Shows: original -> PII detected -> redacted (what Gemini sees) -> response -> rehydrated.
//
// Run: go run ./cmd/demo/
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/enterprise/pii-gateway/internal/pii"
	"github.com/enterprise/pii-gateway/internal/provider"
	"github.com/enterprise/pii-gateway/pkg/models"
)

func main() {
	fmt.Println("==============================================================")
	fmt.Println("   PII REDACTOR GATEWAY -- REAL GEMINI API DEMO")
	fmt.Println("==============================================================")

	// --- Load API Key ---
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		// Try reading from api.key.txt
		data, err := os.ReadFile("api.key.txt")
		if err == nil {
			apiKey = strings.TrimSpace(string(data))
		}
	}
	if apiKey == "" {
		fmt.Println("[ERROR] No API key found. Set GEMINI_API_KEY env var or create api.key.txt")
		os.Exit(1)
	}
	fmt.Printf("[OK] API key loaded (length: %d)\n\n", len(apiKey))

	// --- Build PII Pipeline ---
	regex := pii.NewRegexDetector()
	blocklist := pii.NewBlocklistDetector([]string{"CONFIDENTIAL", "TOP SECRET"})
	allowlist := pii.NewAllowlist([]string{"safe@example.com"})
	pipeline := pii.NewPipeline(
		[]pii.Detector{regex, blocklist},
		0.8,
		allowlist,
		50_000_000, // 50ms
	)
	redactor := pii.NewRedactor()
	rehydrator := pii.NewRehydrator()
	adapter := &provider.GeminiAdapter{}

	// --- Test Cases with REAL PII ---
	testCases := []struct {
		name string
		text string
	}{
		{
			name: "EMAIL + SSN + PHONE",
			text: "Hi, my name is John Smith. My email is john.smith@acmecorp.com, SSN is 123-45-6789, and phone is (555) 123-4567. Summarize what info I gave you.",
		},
		{
			name: "BLOCKLIST TERMS",
			text: "This project is CONFIDENTIAL. The codename is TOP SECRET. Just say OK and repeat the classification level.",
		},
	}

	for i, tc := range testCases {
		fmt.Printf("--- TEST %d: %s ----------------------------------------\n", i+1, tc.name)

		// Create per-request token map.
		tokenMap, err := pii.NewTokenMap()
		if err != nil {
			fmt.Printf("[ERROR] TokenMap: %v\n", err)
			continue
		}

		// STEP 1: Show original text.
		fmt.Printf("\n  [STEP 1] ORIGINAL USER MESSAGE:\n")
		fmt.Printf("  >> %s\n", tc.text)

		// STEP 2: Detect PII.
		matches := pipeline.Detect(tc.text)
		fmt.Printf("\n  [STEP 2] PII DETECTED: %d items\n", len(matches))
		for _, m := range matches {
			fmt.Printf("    * Type: %-12s Value: %-30q Confidence: %.0f%%  Detector: %s\n",
				m.Type, m.Value, m.Confidence*100, m.DetectorName)
		}

		// STEP 3: Redact PII.
		redactedText := tc.text
		if len(matches) > 0 {
			redactedText, _ = redactor.Redact(tc.text, matches, tokenMap)
		}
		fmt.Printf("\n  [STEP 3] REDACTED TEXT (what Gemini will see):\n")
		fmt.Printf("  >> %s\n", redactedText)

		// STEP 4: Build Gemini request with redacted text.
		geminiReq := map[string]interface{}{
			"contents": []map[string]interface{}{
				{
					"role": "user",
					"parts": []map[string]interface{}{
						{"text": redactedText},
					},
				},
			},
		}
		reqBody, _ := json.Marshal(geminiReq)

		// STEP 5: Send REAL request to Gemini API.
		url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=%s", apiKey)
		fmt.Printf("\n  [STEP 4] SENDING TO REAL GEMINI API...\n")

		start := time.Now()
		resp, err := http.Post(url, "application/json", bytes.NewReader(reqBody))
		latency := time.Since(start)

		if err != nil {
			fmt.Printf("  [ERROR] Request failed: %v\n", err)
			tokenMap.Clear()
			continue
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		fmt.Printf("  [OK] Response received (status: %d, latency: %s)\n", resp.StatusCode, latency.Round(time.Millisecond))

		if resp.StatusCode != 200 {
			fmt.Printf("  [ERROR] Gemini API error: %s\n", string(respBody))
			tokenMap.Clear()
			continue
		}

		// STEP 6: Extract response text.
		respFields, err := adapter.ExtractResponseText(respBody)
		if err != nil {
			fmt.Printf("  [ERROR] Parse response: %v\n", err)
			tokenMap.Clear()
			continue
		}

		// Show raw Gemini response (before rehydration).
		fmt.Printf("\n  [STEP 5] GEMINI RAW RESPONSE:\n")
		for key, text := range respFields {
			fmt.Printf("  [%s]:\n  >> %s\n", key, text)
		}

		// STEP 7: Rehydrate response.
		fmt.Printf("\n  [STEP 6] REHYDRATED RESPONSE (PII tokens restored):\n")
		for key, text := range respFields {
			rehydrated := rehydrator.Rehydrate(text, tokenMap)
			fmt.Printf("  [%s]:\n  >> %s\n", key, rehydrated)
		}

		// Security summary.
		fmt.Printf("\n  [SECURITY SUMMARY]\n")
		fmt.Printf("    PII items detected:    %d\n", len(matches))
		fmt.Printf("    Tokens in map:         %d\n", tokenMap.Count())
		fmt.Printf("    PII encrypted in mem:  YES (AES-256-GCM)\n")

		// Check if any original PII leaked into what we sent.
		leaked := false
		for _, m := range matches {
			if strings.Contains(string(reqBody), m.Value) {
				fmt.Printf("    [FAIL] PII %q leaked!\n", m.Value)
				leaked = true
			}
		}
		if !leaked && len(matches) > 0 {
			fmt.Printf("    [PASS] No PII leaked to Gemini!\n")
		}

		tokenMap.Clear()
		fmt.Println()
	}

	fmt.Println("==============================================================")
	fmt.Println("                    DEMO COMPLETE")
	fmt.Println("==============================================================")
}

// Helper to check PII types from matches.
func piiTypes(matches []models.PIIMatch) string {
	types := make(map[string]bool)
	for _, m := range matches {
		types[m.Type] = true
	}
	var result []string
	for t := range types {
		result = append(result, t)
	}
	return strings.Join(result, ", ")
}
