package provider

import (
	"time"

	"github.com/sony/gobreaker"
)

// NewCircuitBreaker creates a circuit breaker for a provider.
// States: Closed → Open (after maxFailures) → Half-Open (after timeout).
func NewCircuitBreaker(name string, maxFailures uint32, timeout time.Duration) *gobreaker.CircuitBreaker {
	settings := gobreaker.Settings{
		Name:        name,
		MaxRequests: 3, // max requests in half-open state
		Interval:    60 * time.Second,
		Timeout:     timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= maxFailures
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			// Metrics recording could be added here.
			_ = name
		},
	}

	return gobreaker.NewCircuitBreaker(settings)
}
