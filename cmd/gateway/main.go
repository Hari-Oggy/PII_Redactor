// PII Redactor Gateway — Entry Point
//
// An enterprise-grade API gateway that sits between the company network
// and external LLM APIs, scrubbing PII from requests before they leave
// the perimeter.
//
// Usage:
//
//	go run ./cmd/gateway/ --config config.yaml
package main

import (
	"flag"
	"log"

	"github.com/enterprise/pii-gateway/internal/config"
	"github.com/enterprise/pii-gateway/internal/server"
	"github.com/enterprise/pii-gateway/internal/zaplog"
	"go.uber.org/zap"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration (atomic.Pointer for hot-reload).
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize structured logger from config.
	zaplog.Init(cfg.Logging.Level, cfg.Logging.Format)
	defer zaplog.Sync()

	zaplog.L().Info("PII Redactor Gateway starting",
		zap.String("proxy_addr", cfg.Server.ProxyAddr),
		zap.String("admin_addr", cfg.Server.AdminAddr),
		zap.Float64("pii_confidence", cfg.PII.ConfidenceThreshold),
		zap.Int("overlap_buffer", cfg.PII.OverlapBufferSize),
		zap.Int("providers", len(cfg.Proxy.Providers)),
	)

	// Build and run the server.
	srv := server.New(cfg)
	if err := srv.Run(); err != nil {
		zaplog.L().Fatal("Server error", zap.Error(err))
	}
}

