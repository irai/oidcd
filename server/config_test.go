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
