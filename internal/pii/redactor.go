package pii

import (
	"sort"

	"github.com/enterprise/pii-gateway/pkg/models"
)

// Redactor replaces detected PII spans in text with HMAC-signed tokens.
// It processes matches from right to left to preserve byte offsets.
type Redactor struct{}

// NewRedactor creates a new Redactor.
func NewRedactor() *Redactor {
	return &Redactor{}
}

// Redact replaces all PII matches in text with tokens, recording mappings
// in the provided TokenMap. Returns the sanitised text and the list of
// redacted spans with their tokens.
func (r *Redactor) Redact(text string, matches []models.PIIMatch, tm *TokenMap) (string, []models.RedactedSpan) {
	if len(matches) == 0 {
		return text, nil
	}

	// Sort matches by start position descending so we can replace
	// from right to left without invalidating earlier offsets.
	sorted := make([]models.PIIMatch, len(matches))
	copy(sorted, matches)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Start > sorted[j].Start
	})

	result := text
	spans := make([]models.RedactedSpan, 0, len(sorted))

	for _, m := range sorted {
		// Get or create a token for this PII value.
		token := tm.Store(m.Value, m.Type)

		// Replace the span in the text.
		result = result[:m.Start] + token + result[m.End:]

		spans = append(spans, models.RedactedSpan{
			PIIMatch: m,
			Token:    token,
		})
	}

	return result, spans
}
