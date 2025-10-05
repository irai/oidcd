package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfigAppliesEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `server:
  public_url: http://localhost:8080
  dev_mode: true
oauth2_clients:
  - client_id: web
    client_secret: s3cret
    redirect_uris: ["http://localhost/callback"]
    scopes: ["openid", "profile"]
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("OIDCD_SERVER_PUBLIC_URL", "https://gateway.example.com")
	t.Setenv("OIDCD_SERVER_ID", "test-server")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if cfg.Server.PublicURL != "https://gateway.example.com" {
		t.Fatalf("PublicURL override mismatch, got %q", cfg.Server.PublicURL)
	}
	if cfg.Server.ServerID != "test-server" {
		t.Fatalf("ServerID override mismatch, got %s", cfg.Server.ServerID)
	}
}

func TestConfigValidateRequiresClient(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OAuth2Clients = nil
	// Should fail when no OAuth2 clients AND no authenticated proxy routes
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error when no oauth2_clients configured and no proxy routes")
	}
}

func TestConfigValidateAllowsProxyOnlyMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OAuth2Clients = nil
	cfg.Proxy.Routes = []ProxyRoute{
		{
			Host:        "demo.example.com",
			Target:      "http://backend:3000",
			RequireAuth: true,
		},
	}
	// Should succeed: proxy mode with auth doesn't require OAuth2 clients
	if err := cfg.Validate(); err != nil {
		t.Fatalf("proxy-only mode should not require oauth2_clients: %v", err)
	}
}

func TestSplitAndTrimRemovesEmpty(t *testing.T) {
	in := " a , ,b,, c "
	out := splitAndTrim(in)
	expected := []string{"a", "b", "c"}
	if len(out) != len(expected) {
		t.Fatalf("unexpected length: got %d want %d", len(out), len(expected))
	}
	for i := range expected {
		if out[i] != expected[i] {
			t.Fatalf("element %d mismatch: got %q want %q", i, out[i], expected[i])
		}
	}
}

func TestParseBoolFallback(t *testing.T) {
	if parseBool("", true) != true {
		t.Fatalf("empty input should return fallback true")
	}
	if parseBool("invalid", false) != false {
		t.Fatalf("invalid input should return fallback false")
	}
	if parseBool("YES", false) != true {
		t.Fatalf("expected true for yes")
	}
	if parseBool("0", true) != false {
		t.Fatalf("expected false for zero")
	}
}

func TestParseDurationFallback(t *testing.T) {
	fallback := 5 * time.Minute
	if parseDuration("bogus", fallback) != fallback {
		t.Fatalf("invalid duration should return fallback")
	}
	if parseDuration("30s", fallback) != 30*time.Second {
		t.Fatalf("parsed duration mismatch")
	}
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `server:
  public_url: http://localhost:8080
  dev_mode: true
  unknown_field: value
oauth2_clients:
  - client_id: web
    redirect_uris: ["http://localhost/callback"]
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatalf("expected error for unknown field")
	}
	if !containsAny(err.Error(), []string{"unknown_field", "not found", "field"}) {
		t.Fatalf("error should mention unknown field, got: %v", err)
	}
}

func TestValidateInvalidPublicURL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.PublicURL = "not-a-url"
	cfg.OAuth2Clients = []ClientConfig{{
		ClientID:     "test",
		RedirectURIs: []string{"http://localhost/callback"},
	}}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected error for invalid public_url")
	}
	if !containsAny(err.Error(), []string{"http://", "https://"}) {
		t.Fatalf("error should mention URL scheme requirement, got: %v", err)
	}
}

func TestValidateInvalidTLSVersion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.TLS.MinVersion = "1.1"
	cfg.OAuth2Clients = []ClientConfig{{
		ClientID:     "test",
		RedirectURIs: []string{"http://localhost/callback"},
	}}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected error for invalid TLS version")
	}
	if !containsAny(err.Error(), []string{"1.2", "1.3"}) {
		t.Fatalf("error should mention valid TLS versions, got: %v", err)
	}
}

func TestValidateMissingClientID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OAuth2Clients = []ClientConfig{{
		ClientID:     "", // Missing
		RedirectURIs: []string{"http://localhost/callback"},
	}}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected error for missing client_id")
	}
	if !containsAny(err.Error(), []string{"client_id"}) {
		t.Fatalf("error should mention client_id, got: %v", err)
	}
}

func TestValidateInvalidRedirectURI(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OAuth2Clients = []ClientConfig{{
		ClientID:     "test",
		RedirectURIs: []string{"not-a-url"},
	}}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected error for invalid redirect URI")
	}
	if !containsAny(err.Error(), []string{"redirect_uri", "http://", "https://"}) {
		t.Fatalf("error should mention redirect URI format, got: %v", err)
	}
}

func TestValidateInvalidProxyTarget(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OAuth2Clients = nil
	cfg.Proxy.Routes = []ProxyRoute{{
		Host:        "demo.example.com",
		Target:      "not-a-url",
		RequireAuth: true,
	}}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected error for invalid proxy target")
	}
	if !containsAny(err.Error(), []string{"target", "http://", "https://"}) {
		t.Fatalf("error should mention target URL format, got: %v", err)
	}
}

func TestValidateInvalidProxyTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OAuth2Clients = nil
	cfg.Proxy.Routes = []ProxyRoute{{
		Host:        "demo.example.com",
		Target:      "http://backend:3000",
		RequireAuth: true,
		Timeout:     "not-a-duration",
	}}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected error for invalid proxy timeout")
	}
	if !containsAny(err.Error(), []string{"timeout", "duration"}) {
		t.Fatalf("error should mention timeout/duration, got: %v", err)
	}
}

func TestValidateMissingDefaultProvider(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.DevMode = false
	cfg.Server.TLS.Domains = []string{"example.com"}
	cfg.Server.Providers.Default = ""
	cfg.OAuth2Clients = []ClientConfig{{
		ClientID:     "test",
		RedirectURIs: []string{"http://localhost/callback"},
	}}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected error for missing default provider in production")
	}
	if !containsAny(err.Error(), []string{"providers.default"}) {
		t.Fatalf("error should mention providers.default, got: %v", err)
	}
}

func TestValidateUnconfiguredDefaultProvider(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Providers.Default = "nonexistent"
	cfg.OAuth2Clients = []ClientConfig{{
		ClientID:     "test",
		RedirectURIs: []string{"http://localhost/callback"},
	}}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected error for unconfigured default provider")
	}
	if !containsAny(err.Error(), []string{"nonexistent", "not configured"}) {
		t.Fatalf("error should mention provider not configured, got: %v", err)
	}
}

func TestValidateProviderMissingIssuer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Providers.Default = "entra"
	cfg.Server.Providers.Entra.Issuer = ""
	cfg.Server.Providers.Entra.ClientID = "test-client"
	cfg.OAuth2Clients = []ClientConfig{{
		ClientID:     "test",
		RedirectURIs: []string{"http://localhost/callback"},
	}}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected error for provider missing issuer")
	}
	if !containsAny(err.Error(), []string{"issuer"}) {
		t.Fatalf("error should mention issuer, got: %v", err)
	}
}

func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if len(substr) > 0 && len(s) >= len(substr) {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}

func TestLoadConfigWithMultipleInvalidValues(t *testing.T) {
	// This test verifies that configuration validation errors are logged
	// with helpful context about what's wrong and how to fix it
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `server:
  server_id: oidcd
  public_url: not-a-valid-url
  dev_listen_addr: 0.0.0.0:8080
  dev_mode: true

  tls:
    min_version: "1.1"

  providers:
    default: entra
    entra:
      issuer: ""
      client_id: test

oauth2_clients:
  - client_id: webapp
    redirect_uris:
      - not-a-valid-url
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Load config should fail with validation errors
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatalf("expected validation errors for invalid config")
	}

	// The error should indicate what's wrong
	// First error will be invalid public_url
	if !containsAny(err.Error(), []string{"public_url", "http://", "https://"}) {
		t.Errorf("error should mention public_url format requirement, got: %v", err)
	}
}

func TestLoadConfigWithInvalidProxyConfiguration(t *testing.T) {
	// Test proxy-specific validation errors
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `server:
  public_url: http://localhost:8080
  dev_mode: true

  providers:
    default: entra
    entra:
      issuer: https://login.microsoftonline.com/tenant/v2.0
      client_id: test-client

oauth2_clients: []

proxy:
  routes:
    - host: demo.example.com
      target: not-a-valid-url
      require_auth: true
      timeout: "invalid-duration"
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatalf("expected validation errors for invalid proxy config")
	}

	// Should complain about invalid target URL first
	if !containsAny(err.Error(), []string{"target", "http://", "https://"}) {
		t.Errorf("error should mention proxy target format, got: %v", err)
	}
}

func TestConfigValidationErrorMessages(t *testing.T) {
	// This test documents all the validation error messages
	// to ensure they provide helpful guidance to users

	tests := []struct {
		name          string
		setupConfig   func(*Config)
		expectedError []string // error should contain one of these strings
		logMessage    string   // what should be logged
	}{
		{
			name: "missing_public_url",
			setupConfig: func(c *Config) {
				c.Server.PublicURL = ""
				c.OAuth2Clients = []ClientConfig{{
					ClientID:     "test",
					RedirectURIs: []string{"http://localhost/callback"},
				}}
			},
			expectedError: []string{"public_url", "required"},
			logMessage:    "Missing required configuration",
		},
		{
			name: "invalid_public_url_format",
			setupConfig: func(c *Config) {
				c.Server.PublicURL = "localhost:8080"
				c.OAuth2Clients = []ClientConfig{{
					ClientID:     "test",
					RedirectURIs: []string{"http://localhost/callback"},
				}}
			},
			expectedError: []string{"http://", "https://"},
			logMessage:    "Invalid configuration value",
		},
		{
			name: "invalid_tls_version",
			setupConfig: func(c *Config) {
				c.Server.TLS.MinVersion = "1.0"
				c.OAuth2Clients = []ClientConfig{{
					ClientID:     "test",
					RedirectURIs: []string{"http://localhost/callback"},
				}}
			},
			expectedError: []string{"1.2", "1.3"},
			logMessage:    "Invalid TLS minimum version",
		},
		{
			name: "missing_oauth2_client_id",
			setupConfig: func(c *Config) {
				c.OAuth2Clients = []ClientConfig{{
					ClientID:     "",
					RedirectURIs: []string{"http://localhost/callback"},
				}}
			},
			expectedError: []string{"client_id"},
			logMessage:    "OAuth2 client missing client_id",
		},
		{
			name: "invalid_redirect_uri",
			setupConfig: func(c *Config) {
				c.OAuth2Clients = []ClientConfig{{
					ClientID:     "test",
					RedirectURIs: []string{"javascript:alert(1)"},
				}}
			},
			expectedError: []string{"redirect_uri", "http://", "https://"},
			logMessage:    "Invalid redirect URI",
		},
		{
			name: "missing_proxy_host",
			setupConfig: func(c *Config) {
				c.OAuth2Clients = nil
				c.Proxy.Routes = []ProxyRoute{{
					Host:        "",
					Target:      "http://backend:3000",
					RequireAuth: true,
				}}
			},
			expectedError: []string{"host", "required"},
			logMessage:    "Proxy route missing host",
		},
		{
			name: "invalid_proxy_timeout",
			setupConfig: func(c *Config) {
				c.OAuth2Clients = nil
				c.Proxy.Routes = []ProxyRoute{{
					Host:        "demo.example.com",
					Target:      "http://backend:3000",
					RequireAuth: true,
					Timeout:     "5 minutes",
				}}
			},
			expectedError: []string{"timeout", "duration"},
			logMessage:    "Invalid proxy route timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.setupConfig(&cfg)

			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected validation error")
			}

			if !containsAny(err.Error(), tt.expectedError) {
				t.Errorf("error should contain one of %v, got: %v", tt.expectedError, err)
			}

			t.Logf("✓ Error message: %v", err)
		})
	}
}
