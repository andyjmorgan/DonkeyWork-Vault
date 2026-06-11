// Package config loads the vault server configuration from the environment. It is env-first (the
// natural fit for a single-container deployment) with defaults chosen so an existing deployment
// keeps the same behaviour.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully-resolved server configuration.
type Config struct {
	ListenAddr    string
	DSN           string
	RunMigrations bool
	WebRoot       string
	PublicBaseURL string

	ActiveKekID string
	Keks        map[string]string

	OIDCAuthority    string
	OIDCInternal     string
	OIDCAudience     string
	OIDCClientID     string
	OIDCScopes       string
	OIDCWebClientID  string
	OIDCCliClientID  string
	OIDCWebScopes    string
	OIDCCliScopes    string
	OIDCRequireHTTPS bool

	TrustedProxies      []string
	AuditChannelCap     int
	AuditBatchSize      int
	AuditFlushInterval  time.Duration
	AuditRetentionDays  int
	AuditSweepInterval  time.Duration
	AuditRetentionBatch int

	OTLPEndpoint   string
	OTLPInsecure   bool
	ServiceVersion string
	Environment    string
}

// Load reads configuration from the environment, applying defaults and validating required values.
func Load() (*Config, error) {
	c := &Config{
		ListenAddr:          getenv("VAULT_LISTEN_ADDR", ":8080"),
		DSN:                 firstNonEmpty(os.Getenv("VAULT_DSN"), os.Getenv("DATABASE_URL"), os.Getenv("VAULT_DB")),
		RunMigrations:       getenvBool("VAULT_RUN_MIGRATIONS", true),
		WebRoot:             os.Getenv("VAULT_WEBROOT"),
		PublicBaseURL:       firstNonEmpty(os.Getenv("VAULT_PUBLIC_BASE_URL"), "https://vault.donkeywork.dev"),
		ActiveKekID:         os.Getenv("VAULT_CRYPTO_ACTIVE_KEK_ID"),
		Keks:                parseKeks(os.Getenv("VAULT_CRYPTO_KEKS")),
		OIDCAuthority:       firstNonEmpty(os.Getenv("VAULT_OIDC_AUTHORITY"), os.Getenv("OIDC_AUTHORITY")),
		OIDCInternal:        os.Getenv("VAULT_OIDC_INTERNAL_AUTHORITY"),
		OIDCAudience:        os.Getenv("VAULT_OIDC_AUDIENCE"),
		OIDCClientID:        os.Getenv("VAULT_OIDC_CLIENT_ID"),
		OIDCScopes:          getenv("VAULT_OIDC_SCOPES", "openid profile email"),
		OIDCWebClientID:     os.Getenv("VAULT_OIDC_WEB_CLIENT_ID"),
		OIDCCliClientID:     os.Getenv("VAULT_OIDC_CLI_CLIENT_ID"),
		OIDCWebScopes:       os.Getenv("VAULT_OIDC_WEB_SCOPES"),
		OIDCCliScopes:       os.Getenv("VAULT_OIDC_CLI_SCOPES"),
		OIDCRequireHTTPS:    getenvBool("VAULT_OIDC_REQUIRE_HTTPS", true),
		TrustedProxies:      splitList(getenv("VAULT_TRUSTED_PROXIES", "10.42.0.0/16,10.43.0.0/16,127.0.0.1/32,::1/128")),
		AuditChannelCap:     getenvInt("VAULT_AUDIT_CHANNEL_CAPACITY", 8192),
		AuditBatchSize:      getenvInt("VAULT_AUDIT_BATCH_SIZE", 100),
		AuditFlushInterval:  time.Duration(getenvInt("VAULT_AUDIT_FLUSH_MS", 500)) * time.Millisecond,
		AuditRetentionDays:  getenvInt("VAULT_AUDIT_RETENTION_DAYS", 180),
		AuditSweepInterval:  time.Duration(getenvInt("VAULT_AUDIT_SWEEP_HOURS", 12)) * time.Hour,
		AuditRetentionBatch: getenvInt("VAULT_AUDIT_RETENTION_BATCH", 5000),
		OTLPEndpoint:        firstNonEmpty(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), os.Getenv("VAULT_OTLP_ENDPOINT")),
		OTLPInsecure:        getenvBool("VAULT_OTLP_INSECURE", false),
		ServiceVersion:      getenv("VAULT_VERSION", "dev"),
		Environment:         getenv("VAULT_ENVIRONMENT", "production"),
	}

	if c.DSN == "" {
		return nil, fmt.Errorf("database DSN is required (set VAULT_DSN or DATABASE_URL)")
	}
	if c.ActiveKekID == "" || len(c.Keks) == 0 {
		return nil, fmt.Errorf("crypto KEK config is required (set VAULT_CRYPTO_ACTIVE_KEK_ID and VAULT_CRYPTO_KEKS)")
	}
	return c, nil
}

// parseKeks parses "id1=base64,id2=base64" into a map.
func parseKeks(raw string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		if eq := strings.IndexByte(pair, '='); eq > 0 {
			out[strings.TrimSpace(pair[:eq])] = strings.TrimSpace(pair[eq+1:])
		}
	}
	return out
}

func splitList(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getenvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
