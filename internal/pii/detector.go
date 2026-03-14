package pii

import (
	"regexp"
	"time"

	"github.com/enterprise/pii-gateway/pkg/models"
)

// Detector is the interface all PII detection strategies must implement.
type Detector interface {
	// Name returns a human-readable identifier for this detector.
	Name() string

	// Detect scans text and returns all PII matches found.
	// Implementations must respect the timeout duration to guard against ReDoS.
	Detect(text string, timeout time.Duration) []models.PIIMatch
}

// Pipeline orchestrates multiple detectors in parallel, merges results,
// applies confidence thresholds, and filters through the allowlist.
type Pipeline struct {
	detectors           []Detector
	confidenceThreshold float64
	allowlist           *Allowlist
	timeout             time.Duration
}

// NewPipeline creates a PII detection pipeline with the given detectors.
func NewPipeline(detectors []Detector, threshold float64, allowlist *Allowlist, timeout time.Duration) *Pipeline {
	return &Pipeline{
		detectors:           detectors,
		confidenceThreshold: threshold,
		allowlist:           allowlist,
		timeout:             timeout,
	}
}

// Detect runs all detectors, merges results, applies threshold and allowlist.
func (p *Pipeline) Detect(text string) []models.PIIMatch {
	if len(text) == 0 {
		return nil
	}

	type result struct {
		matches []models.PIIMatch
	}

	ch := make(chan result, len(p.detectors))

	// Run each detector concurrently with timeout.
	for _, d := range p.detectors {
		go func(det Detector) {
			matches := det.Detect(text, p.timeout)
			ch <- result{matches: matches}
		}(d)
	}

	// Collect all results.
	var allMatches []models.PIIMatch
	for range p.detectors {
		r := <-ch
		allMatches = append(allMatches, r.matches...)
	}

	// De-duplicate overlapping spans (keep highest confidence).
	allMatches = deduplicateSpans(allMatches)

	// Filter by confidence threshold.
	var filtered []models.PIIMatch
	for _, m := range allMatches {
		if m.Confidence >= p.confidenceThreshold {
			// Check allowlist — skip known safe terms.
			if p.allowlist != nil && p.allowlist.IsSafe(m.Value) {
				continue
			}
			filtered = append(filtered, m)
		}
	}

	return filtered
}

// deduplicateSpans removes overlapping PII matches, keeping the one
// with the highest confidence score.
func deduplicateSpans(matches []models.PIIMatch) []models.PIIMatch {
	if len(matches) <= 1 {
		return matches
	}

	// Sort by start position, then by confidence descending.
	// Simple O(n²) for now — PII count per request is small.
	var result []models.PIIMatch
	used := make([]bool, len(matches))

	for i := 0; i < len(matches); i++ {
		if used[i] {
			continue
		}
		best := i
		for j := i + 1; j < len(matches); j++ {
			if used[j] {
				continue
			}
			// Check overlap.
			if overlaps(matches[best], matches[j]) {
				if matches[j].Confidence > matches[best].Confidence {
					used[best] = true
					best = j
				} else {
					used[j] = true
				}
			}
		}
		result = append(result, matches[best])
		used[best] = true
	}

	return result
}

// overlaps returns true if two PII matches share any character positions.
func overlaps(a, b models.PIIMatch) bool {
	return a.Start < b.End && b.Start < a.End
}

// compileRegexSafe compiles a regex pattern, returning nil on failure.
func compileRegexSafe(pattern string) *regexp.Regexp {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re
}
