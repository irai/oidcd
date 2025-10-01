package server

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func TestNewAppKeepsConfiguredDefaultProvider(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.DevMode = true
	cfg.Clients = []ClientConfig{{
		ClientID:     "test-client",
		RedirectURIs: []string{"http://localhost/callback"},
		Scopes:       []string{"openid"},
		Audiences:    []string{"api://default"},
	}}
	cfg.Providers.Default = "entra"
	cfg.Providers.Entra = UpstreamProvider{}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	app, err := NewApp(context.Background(), cfg, logger)
	if err != nil {
		t.Fatalf("NewApp returned error: %v", err)
	}

	if app.DefaultProvider != "entra" {
		t.Fatalf("expected default provider to remain 'entra', got %q", app.DefaultProvider)
	}
}
