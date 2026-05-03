package pii

import (
	"log"
)

// CircuitBreakingTokenMap wraps a RedisTokenMap and an InMemoryTokenMap fallback.
// If the primary (Redis) fails, it transparently degrades to the in-memory fallback
// to prevent gateway requests from failing.
type CircuitBreakingTokenMap struct {
	primary  TokenMap
	fallback TokenMap
}

// NewCircuitBreakingTokenMap creates a resilient token map.
func NewCircuitBreakingTokenMap(primary, fallback TokenMap) *CircuitBreakingTokenMap {
	return &CircuitBreakingTokenMap{
		primary:  primary,
		fallback: fallback,
	}
}

func (c *CircuitBreakingTokenMap) Store(piiValue, piiType string) string {
	// Try primary
	token := c.primary.Store(piiValue, piiType)
	if token != "" {
		return token
	}

	// Fallback
	log.Printf("WARN: Primary TokenMap failed to Store, falling back to memory")
	return c.fallback.Store(piiValue, piiType)
}

func (c *CircuitBreakingTokenMap) Lookup(token string) (string, bool) {
	val, ok := c.primary.Lookup(token)
	if ok {
		return val, true
	}
	return c.fallback.Lookup(token)
}

func (c *CircuitBreakingTokenMap) VerifyAndLookup(token string) (string, bool) {
	val, ok := c.primary.VerifyAndLookup(token)
	if ok {
		return val, true
	}
	return c.fallback.VerifyAndLookup(token)
}

func (c *CircuitBreakingTokenMap) Count() int {
	return c.primary.Count() + c.fallback.Count()
}

func (c *CircuitBreakingTokenMap) Clear() {
	c.primary.Clear()
	c.fallback.Clear()
}
