package pii

import (
	"strings"
)

// Allowlist holds terms that should NOT be flagged as PII.
// Used to reduce false positives (e.g., "Jordan" as a country, not a name).
type Allowlist struct {
	terms map[string]struct{}
}

// NewAllowlist creates an allowlist from the given safe terms.
func NewAllowlist(terms []string) *Allowlist {
	m := make(map[string]struct{}, len(terms))
	for _, t := range terms {
		m[strings.ToLower(t)] = struct{}{}
	}
	return &Allowlist{terms: m}
}

// IsSafe returns true if the given value is in the allowlist.
func (a *Allowlist) IsSafe(value string) bool {
	_, ok := a.terms[strings.ToLower(value)]
	return ok
}
