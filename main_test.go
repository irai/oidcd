package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"oidcd/server"
)

type stubProvider struct {
	url string
}

func (s *stubProvider) AuthCodeURL(state, nonce, codeChallenge, method string) string {
	return s.url
}

func (s *stubProvider) Exchange(ctx context.Context, code, expectedNonce string) (server.ProviderUser, error) {
	return server.ProviderUser{}, nil
}

func TestRunConnectSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/login", http.StatusFound)
		case "/login":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("login"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	providers := map[string]server.IdentityProvider{
		"stub": &stubProvider{url: srv.URL + "/start"},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := server.DefaultConfig()

	if err := runConnect(context.Background(), cfg, logger, "stub", providers, nil); err != nil {
		t.Fatalf("runConnect returned error: %v", err)
	}
}

func TestRunConnectFailureStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	providers := map[string]server.IdentityProvider{
		"stub": &stubProvider{url: srv.URL},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := server.DefaultConfig()

	if err := runConnect(context.Background(), cfg, logger, "stub", providers, nil); err == nil {
		t.Fatalf("expected error but got nil")
	}
}

func TestRunConnectMissingProvider(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := server.DefaultConfig()

	if err := runConnect(context.Background(), cfg, logger, "missing", map[string]server.IdentityProvider{}, nil); err == nil {
		t.Fatalf("expected error for missing provider")
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := map[string]slog.Level{
		"":        slog.LevelInfo,
		"INFO":    slog.LevelInfo,
		"debug":   slog.LevelDebug,
		"Warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"ERR":     slog.LevelError,
	}

	for input, want := range tests {
		got, err := parseLogLevel(input)
		if err != nil {
			t.Fatalf("parseLogLevel(%q) returned error: %v", input, err)
		}
		if got != want {
			t.Fatalf("parseLogLevel(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestParseLogLevelInvalid(t *testing.T) {
	if _, err := parseLogLevel("trace"); err == nil {
		t.Fatalf("expected error for unsupported level")
	}
}
