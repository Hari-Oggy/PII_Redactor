package pii

import (
	"strings"
	"sync"
	"time"

	"github.com/enterprise/pii-gateway/pkg/models"
)

// BlocklistDetector detects PII by matching against a list of explicitly
// blocked terms (e.g., "CONFIDENTIAL", "TOP SECRET", company-specific terms).
type BlocklistDetector struct {
	mu    sync.RWMutex
	terms []string
}

// NewBlocklistDetector creates a detector with the given blocked terms.
func NewBlocklistDetector(terms []string) *BlocklistDetector {
	lower := make([]string, len(terms))
	for i, t := range terms {
		lower[i] = strings.ToLower(t)
	}
	return &BlocklistDetector{terms: lower}
}

// Name returns the detector name.
func (d *BlocklistDetector) Name() string {
	return "blocklist"
}

// Detect scans text for any blocklisted terms (case-insensitive).
func (d *BlocklistDetector) Detect(text string, _ time.Duration) []models.PIIMatch {
	d.mu.RLock()
	terms := d.terms
	d.mu.RUnlock()

	var matches []models.PIIMatch
	lowerText := strings.ToLower(text)

	for _, term := range terms {
		start := 0
		for {
			idx := strings.Index(lowerText[start:], term)
			if idx == -1 {
				break
			}
			absStart := start + idx
			absEnd := absStart + len(term)
			matches = append(matches, models.PIIMatch{
				Type:         "blocklist",
				Start:        absStart,
				End:          absEnd,
				Value:        text[absStart:absEnd],
				Confidence:   1.0, // exact match = full confidence
				DetectorName: "blocklist",
			})
			start = absEnd
		}
	}

	return matches
}

// AddTerms appends new terms to the blocklist (thread-safe).
func (d *BlocklistDetector) AddTerms(terms []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, t := range terms {
		d.terms = append(d.terms, strings.ToLower(t))
	}
}

// ClearTerms removes all terms from the blocklist (thread-safe).
func (d *BlocklistDetector) ClearTerms() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.terms = nil
}

// GetTerms returns a copy of the current blocklist (thread-safe).
func (d *BlocklistDetector) GetTerms() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]string, len(d.terms))
	copy(out, d.terms)
	return out
}

