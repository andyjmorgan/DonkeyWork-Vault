package config

import (
	"testing"
)

func TestLoadDefaultsAndRequired(t *testing.T) {
	t.Setenv("VAULT_DSN", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("VAULT_DB", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected DSN required error")
	}

	t.Setenv("VAULT_DSN", "postgres://x")
	t.Setenv("VAULT_CRYPTO_ACTIVE_KEK_ID", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected crypto required error")
	}

	t.Setenv("VAULT_CRYPTO_ACTIVE_KEK_ID", "local:v1")
	t.Setenv("VAULT_CRYPTO_KEKS", "local:v1=abc, local:v2=def ,")
	t.Setenv("VAULT_AUDIT_BATCH_SIZE", "25")
	t.Setenv("VAULT_RUN_MIGRATIONS", "false")
	t.Setenv("VAULT_OIDC_REQUIRE_HTTPS", "false")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":8080" || c.PublicBaseURL == "" {
		t.Fatalf("defaults: %+v", c)
	}
	if len(c.Keks) != 2 || c.Keks["local:v1"] != "abc" {
		t.Fatalf("keks: %+v", c.Keks)
	}
	if c.AuditBatchSize != 25 || c.RunMigrations || c.OIDCRequireHTTPS {
		t.Fatalf("overrides not applied: %+v", c)
	}
	if len(c.TrustedProxies) == 0 {
		t.Fatal("trusted proxies default")
	}
}

func TestGetenvHelpers(t *testing.T) {
	t.Setenv("X_INT_BAD", "notnum")
	if getenvInt("X_INT_BAD", 7) != 7 {
		t.Fatal("int fallback")
	}
	t.Setenv("X_BOOL_BAD", "maybe")
	if !getenvBool("X_BOOL_BAD", true) {
		t.Fatal("bool fallback")
	}
	if getenv("X_UNSET_ABC", "def") != "def" {
		t.Fatal("string fallback")
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	t.Setenv("VAULT_DSN", "postgres://x")
	t.Setenv("VAULT_CRYPTO_ACTIVE_KEK_ID", "local:v1")
	t.Setenv("VAULT_CRYPTO_KEKS", "local:v1=abc")
	t.Setenv("VAULT_LISTEN_ADDR", "127.0.0.1:9999")
	t.Setenv("VAULT_OIDC_AUTHORITY", "https://idp")
	t.Setenv("VAULT_OIDC_WEB_CLIENT_ID", "web")
	t.Setenv("VAULT_OIDC_CLI_CLIENT_ID", "cli")
	t.Setenv("VAULT_TRUSTED_PROXIES", "10.0.0.0/8")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "collector:4318")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != "127.0.0.1:9999" || c.OIDCAuthority != "https://idp" || c.OIDCWebClientID != "web" {
		t.Fatalf("overrides: %+v", c)
	}
	if len(c.TrustedProxies) != 1 || c.OTLPEndpoint != "collector:4318" {
		t.Fatalf("proxies/otlp: %+v", c)
	}
}
