package pii

import "github.com/enterprise/pii-gateway/pkg/models"

// ConfidenceFilter filters PII matches by a minimum confidence threshold.
// Matches below the threshold are discarded.
type ConfidenceFilter struct {
	Threshold float64
}

// Filter returns only matches that meet or exceed the confidence threshold.
func (f *ConfidenceFilter) Filter(matches []models.PIIMatch) []models.PIIMatch {
	if f.Threshold <= 0 {
		return matches
	}
	var result []models.PIIMatch
	for _, m := range matches {
		if m.Confidence >= f.Threshold {
			result = append(result, m)
		}
	}
	return result
}
