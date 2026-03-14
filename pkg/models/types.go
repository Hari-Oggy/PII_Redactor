// Package models provides shared data types used across the PII gateway.
package models

// PIIMatch represents a single detected PII span in text.
type PIIMatch struct {
	// Type of PII detected (e.g., "email", "ssn", "phone", "credit_card", "name").
	Type string `json:"type"`

	// Start is the byte offset of the PII span start in the original text.
	Start int `json:"start"`

	// End is the byte offset of the PII span end (exclusive) in the original text.
	End int `json:"end"`

	// Value is the actual PII text matched.
	Value string `json:"value"`

	// Confidence score from 0.0 to 1.0 indicating detection certainty.
	Confidence float64 `json:"confidence"`

	// DetectorName identifies which detector found this match.
	DetectorName string `json:"detector_name"`
}

// RedactedSpan represents a PII span that has been replaced with a token.
type RedactedSpan struct {
	PIIMatch

	// Token is the replacement placeholder (UUID + HMAC).
	Token string `json:"token"`
}

// ProviderType enumerates supported LLM API providers.
type ProviderType string

const (
	ProviderOpenAI    ProviderType = "openai"
	ProviderAnthropic ProviderType = "anthropic"
	ProviderAzure     ProviderType = "azure"
	ProviderGemini    ProviderType = "gemini"
)

// NormalisedContent holds text extracted from provider-specific request/response
// bodies in a provider-agnostic format for PII scanning.
type NormalisedContent struct {
	// Fields maps a JSON path (e.g., "messages.0.content") to its text value.
	Fields map[string]string
}

// AuditEntry represents a single auditable event in the gateway.
type AuditEntry struct {
	// RequestID is the correlation ID (X-Request-ID) for this request.
	RequestID string `json:"request_id"`

	// Timestamp in RFC3339 format.
	Timestamp string `json:"timestamp"`

	// UserID identifies the authenticated user (from JWT sub claim).
	UserID string `json:"user_id"`

	// Provider is the target LLM provider.
	Provider ProviderType `json:"provider"`

	// PIIDetected is the count of PII spans found and redacted.
	PIIDetected int `json:"pii_detected"`

	// PIITypes lists the types of PII detected (e.g., ["email", "ssn"]).
	PIITypes []string `json:"pii_types"`

	// RequestRedacted is the sanitised request body (PII replaced with tokens).
	RequestRedacted string `json:"request_redacted"`

	// StatusCode is the HTTP status code returned by the LLM.
	StatusCode int `json:"status_code"`

	// Latency in milliseconds for the full proxy round-trip.
	LatencyMs int64 `json:"latency_ms"`
}
