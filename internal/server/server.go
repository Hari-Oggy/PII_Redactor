// Package server manages the dual-port HTTP server setup:
// - Proxy port (:8080) for employee traffic with full middleware chain
// - Admin port (:9090, loopback) for health probes and management
package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/enterprise/pii-gateway/internal/admin"
	"github.com/enterprise/pii-gateway/internal/audit"
	"github.com/enterprise/pii-gateway/internal/config"
	"github.com/enterprise/pii-gateway/internal/middleware"
	"github.com/enterprise/pii-gateway/internal/pii"
	"github.com/enterprise/pii-gateway/internal/provider"
	"github.com/enterprise/pii-gateway/internal/proxy"
)

// Server holds both the proxy and admin HTTP servers.
type Server struct {
	proxyServer *http.Server
	adminServer *http.Server
	cfg         *config.Config
}

// New creates a fully-wired Server with all middleware and handlers.
func New(cfg *config.Config) *Server {
	// === Build PII Engine ===
	regexDetector := pii.NewRegexDetector()
	blocklistDetector := pii.NewBlocklistDetector(cfg.PII.Blocklist)
	allowlist := pii.NewAllowlist(cfg.PII.Allowlist)

	detectors := []pii.Detector{regexDetector, blocklistDetector}
	pipeline := pii.NewPipeline(detectors, cfg.PII.ConfidenceThreshold, allowlist, cfg.PII.RegexTimeout)
	redactor := pii.NewRedactor()
	rehydrator := pii.NewRehydrator()

	// === Build Audit Logger ===
	auditPath := os.Getenv("AUDIT_LOG_PATH")
	auditLogger, err := audit.NewLogger(auditPath)
	if err != nil {
		log.Printf("WARN: failed to create audit logger: %v, using stdout", err)
		auditLogger, _ = audit.NewLogger("")
	}

	// === Build Provider Registry ===
	registry := provider.NewRegistry()

	// === Build SSRF-safe Transport ===
	// Collect allowed domains from provider configs for egress firewall.
	var allowedDomains []string
	for _, p := range cfg.Proxy.Providers {
		if p.BaseURL != "" {
			// Extract domain from base URL.
			domain := strings.TrimPrefix(p.BaseURL, "https://")
			domain = strings.TrimPrefix(domain, "http://")
			if idx := strings.Index(domain, "/"); idx > 0 {
				domain = domain[:idx]
			}
			allowedDomains = append(allowedDomains, domain)
		}
	}
	safeTransport := middleware.SafeTransport(allowedDomains)

	// === Build Proxy Handler ===
	proxyHandler := proxy.NewHandler(registry, pipeline, redactor, rehydrator, auditLogger, safeTransport, cfg)

	// === Build Rate Limiter ===
	rateLimiter := middleware.NewRateLimiter(1000, 2000) // 1000 req/s, burst 2000

	// === Build Proxy Router (chi) ===
	r := chi.NewRouter()

	// Middleware chain (order matters).
	r.Use(middleware.Recovery)
	r.Use(middleware.Correlation)
	r.Use(middleware.Logging)
	r.Use(middleware.Metrics)
	r.Use(middleware.Auth)
	r.Use(rateLimiter.Middleware)
	r.Use(middleware.BodyLimit)

	// Prompt injection detection (flag mode — logs but allows through).
	r.Use(middleware.PromptGuard("flag"))

	// TokenMap middleware — creates per-request token map in context.
	r.Use(pii.TokenMapMiddleware)

	// Header + query param PII scanning.
	tokenMapFn := func(r *http.Request) *pii.TokenMap {
		return pii.GetTokenMap(r.Context())
	}
	r.Use(middleware.HeaderScan(pipeline, redactor, tokenMapFn))

	// Multipart file upload scanning.
	r.Use(middleware.MultipartScanner(pipeline))

	// Semaphore for bounded concurrency.
	sem := make(chan struct{}, cfg.Server.MaxConcurrency)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				next.ServeHTTP(w, r)
			default:
				http.Error(w, `{"error":"service overloaded"}`, http.StatusServiceUnavailable)
			}
		})
	})

	// All other routes go to the proxy handler.
	r.Handle("/*", proxyHandler)

	// === Build Admin Server ===
	adminMux := http.NewServeMux()
	adminHandler := admin.NewHandler(blocklistDetector, pipeline)
	adminHandler.RegisterRoutes(adminMux)
	// Metrics endpoint on admin port (not public proxy port).
	adminMux.Handle("/metrics", middleware.MetricsHandler())

	// === Create HTTP Servers ===
	proxyServer := &http.Server{
		Addr:         cfg.Server.ProxyAddr,
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	adminServer := &http.Server{
		Addr:         cfg.Server.AdminAddr,
		Handler:      adminMux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return &Server{
		proxyServer: proxyServer,
		adminServer: adminServer,
		cfg:         cfg,
	}
}

// Run starts both servers and blocks until shutdown signal.
func (s *Server) Run() error {
	// Channel for server errors.
	errCh := make(chan error, 2)

	// Start admin server.
	go func() {
		log.Printf("Admin server listening on %s", s.cfg.Server.AdminAddr)
		if err := s.adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("admin server: %w", err)
		}
	}()

	// Start proxy server.
	go func() {
		log.Printf("Proxy server listening on %s", s.cfg.Server.ProxyAddr)

		// mTLS support.
		if s.cfg.Server.TLSCertFile != "" && s.cfg.Server.TLSKeyFile != "" {
			log.Printf("TLS enabled (cert: %s)", s.cfg.Server.TLSCertFile)
			if err := s.proxyServer.ListenAndServeTLS(
				s.cfg.Server.TLSCertFile,
				s.cfg.Server.TLSKeyFile,
			); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("proxy server (TLS): %w", err)
			}
		} else {
			if err := s.proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("proxy server: %w", err)
			}
		}
	}()

	// Wait for interrupt signal or server error.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-quit:
		log.Printf("Received signal %s, shutting down gracefully...", sig)
	}

	// Graceful shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Server.ShutdownTimeout)
	defer cancel()

	// Shutdown proxy first (stop accepting new requests).
	if err := s.proxyServer.Shutdown(ctx); err != nil {
		log.Printf("Proxy server shutdown error: %v", err)
	}

	// Then shutdown admin.
	if err := s.adminServer.Shutdown(ctx); err != nil {
		log.Printf("Admin server shutdown error: %v", err)
	}

	log.Println("Server shutdown complete")
	return nil
}
