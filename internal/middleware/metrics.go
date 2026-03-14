package middleware

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pii_gateway_http_requests_total",
			Help: "Total number of HTTP requests processed",
		},
		[]string{"method", "path", "status"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "pii_gateway_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	piiDetectionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pii_gateway_pii_detections_total",
			Help: "Total number of PII detections by type",
		},
		[]string{"type", "detector"},
	)

	activeConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "pii_gateway_active_connections",
			Help: "Number of active connections",
		},
	)

	circuitBreakerState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pii_gateway_circuit_breaker_state",
			Help: "Circuit breaker state (0=closed, 1=half-open, 2=open)",
		},
		[]string{"provider"},
	)
)

// MetricsHandler returns the Prometheus metrics HTTP handler.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// Metrics middleware records request count and latency.
func Metrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		activeConnections.Inc()
		defer activeConnections.Dec()

		timer := prometheus.NewTimer(httpRequestDuration.WithLabelValues(r.Method, r.URL.Path))
		defer timer.ObserveDuration()

		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)

		httpRequestsTotal.WithLabelValues(
			r.Method,
			r.URL.Path,
			http.StatusText(sw.status),
		).Inc()
	})
}

// RecordPIIDetection records a PII detection metric.
func RecordPIIDetection(piiType, detector string) {
	piiDetectionsTotal.WithLabelValues(piiType, detector).Inc()
}

// RecordCircuitBreakerState records the circuit breaker state for a provider.
func RecordCircuitBreakerState(provider string, state float64) {
	circuitBreakerState.WithLabelValues(provider).Set(state)
}
