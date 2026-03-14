// Package config provides configuration loading with hot-reload support
// using copy-on-write atomic swaps to ensure in-flight requests see
// consistent configuration snapshots.
package config

import (
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// Config is the top-level, immutable configuration struct.
// It is swapped atomically via atomic.Pointer on hot-reload.
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Proxy    ProxyConfig    `mapstructure:"proxy"`
	PII      PIIConfig      `mapstructure:"pii"`
	Auth     AuthConfig     `mapstructure:"auth"`
	Admin    AdminConfig    `mapstructure:"admin"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Metrics  MetricsConfig  `mapstructure:"metrics"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	ProxyAddr        string        `mapstructure:"proxy_addr"`         // e.g. ":8080"
	AdminAddr        string        `mapstructure:"admin_addr"`         // e.g. "127.0.0.1:9090"
	ReadTimeout      time.Duration `mapstructure:"read_timeout"`
	WriteTimeout     time.Duration `mapstructure:"write_timeout"`
	IdleTimeout      time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout  time.Duration `mapstructure:"shutdown_timeout"`
	MaxConcurrency   int           `mapstructure:"max_concurrency"`    // semaphore size
	MaxBodyBytes     int64         `mapstructure:"max_body_bytes"`     // body size limit
	TLSCertFile      string        `mapstructure:"tls_cert_file"`
	TLSKeyFile       string        `mapstructure:"tls_key_file"`
	TLSClientCAFile  string        `mapstructure:"tls_client_ca_file"` // mTLS
}

// ProxyConfig holds upstream proxy settings.
type ProxyConfig struct {
	UpstreamTimeout time.Duration `mapstructure:"upstream_timeout"` // e.g. 120s
	Providers       []ProviderConfig `mapstructure:"providers"`
}

// ProviderConfig holds per-provider upstream settings.
type ProviderConfig struct {
	Name              string        `mapstructure:"name"`              // "openai", "anthropic", "azure"
	BaseURL           string        `mapstructure:"base_url"`
	APIKeyEnv         string        `mapstructure:"api_key_env"`       // env var name holding the key
	PathPrefix        string        `mapstructure:"path_prefix"`       // route prefix, e.g. "/openai"
	CircuitBreaker    CBConfig      `mapstructure:"circuit_breaker"`
}

// CBConfig configures the circuit breaker for a provider.
type CBConfig struct {
	MaxFailures       uint32        `mapstructure:"max_failures"`      // failures before open
	Timeout           time.Duration `mapstructure:"timeout"`           // open → half-open wait
	MaxHalfOpen       uint32        `mapstructure:"max_half_open"`     // requests in half-open
}

// PIIConfig holds PII detection and redaction settings.
type PIIConfig struct {
	ConfidenceThreshold float64       `mapstructure:"confidence_threshold"` // e.g. 0.8
	RegexTimeout        time.Duration `mapstructure:"regex_timeout"`        // ReDoS guard, e.g. 50ms
	OverlapBufferSize   int           `mapstructure:"overlap_buffer_size"`  // e.g. 128
	Blocklist           []string      `mapstructure:"blocklist"`            // custom blocked terms
	Allowlist           []string      `mapstructure:"allowlist"`            // false-positive safe terms
	ScanHeaders         []string      `mapstructure:"scan_headers"`         // headers to scan for PII
	ScanQueryParams     bool          `mapstructure:"scan_query_params"`
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	Enabled          bool     `mapstructure:"enabled"`
	JWTSecret        string   `mapstructure:"jwt_secret"`
	JWTPublicKeyFile string   `mapstructure:"jwt_public_key_file"`
	APIKeys          []string `mapstructure:"api_keys"`            // static API key list
}

// AdminConfig holds admin API settings.
type AdminConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	APIKey  string `mapstructure:"api_key"` // separate auth for admin
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level  string `mapstructure:"level"`  // "debug", "info", "warn", "error"
	Format string `mapstructure:"format"` // "json" or "console"
}

// MetricsConfig holds Prometheus metrics settings.
type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"` // e.g. "/metrics"
}

// configPtr is the global atomic pointer to the current Config.
var configPtr atomic.Pointer[Config]

// Get returns the current immutable Config snapshot.
// Safe for concurrent use — in-flight requests will see consistent config.
func Get() *Config {
	return configPtr.Load()
}

// Load reads configuration from the given file path and sets defaults.
func Load(path string) (*Config, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("server.proxy_addr", ":8080")
	v.SetDefault("server.admin_addr", "127.0.0.1:9090")
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "120s")
	v.SetDefault("server.idle_timeout", "60s")
	v.SetDefault("server.shutdown_timeout", "15s")
	v.SetDefault("server.max_concurrency", 10000)
	v.SetDefault("server.max_body_bytes", 10*1024*1024) // 10 MB
	v.SetDefault("proxy.upstream_timeout", "120s")
	v.SetDefault("pii.confidence_threshold", 0.8)
	v.SetDefault("pii.regex_timeout", "50ms")
	v.SetDefault("pii.overlap_buffer_size", 128)
	v.SetDefault("pii.scan_query_params", true)
	v.SetDefault("pii.scan_headers", []string{"X-User-Email", "X-User-Name"})
	v.SetDefault("auth.enabled", true)
	v.SetDefault("admin.enabled", true)
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("metrics.enabled", true)
	v.SetDefault("metrics.path", "/metrics")

	v.SetConfigFile(path)
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	// Atomic store — safe for concurrent readers.
	configPtr.Store(cfg)

	// Watch for changes — copy-on-write reload.
	v.OnConfigChange(func(e fsnotify.Event) {
		newCfg := &Config{}
		if err := v.Unmarshal(newCfg); err != nil {
			log.Printf("ERROR: config reload failed: %v", err)
			return
		}
		configPtr.Store(newCfg)
		log.Printf("INFO: config reloaded from %s", path)
	})
	v.WatchConfig()

	return cfg, nil
}
