package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"testing"
	"time"
)

func newTestTokenService(t *testing.T) (*TokenService, *InMemoryStore, *Client) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Server.PublicURL = "http://gateway.test"
	cfg.Tokens.AccessTTL = time.Minute
	cfg.Tokens.RefreshTTL = 24 * time.Hour
	cfg.Tokens.RotateRefresh = true

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewInMemoryStore()
	jwks, err := NewJWKSManager(cfg.Keys, logger)
	if err != nil {
		t.Fatalf("NewJWKSManager: %v", err)
	}

	ts := NewTokenService(cfg, store, jwks, logger)
	client := &Client{
		ClientID:     "client",
		ClientSecret: "secret",
		Scopes:       []string{"openid", "profile"},
		Audiences:    []string{"api://default"},
	}
	return ts, store, client
}

func TestMintForAuthorizationCodeAndValidate(t *testing.T) {
	ts, _, client := newTestTokenService(t)
	code := AuthorizationCode{
		Code:      "code",
		ClientID:  client.ClientID,
		Scope:     "openid profile",
		SessionID: "session",
		UserID:    "stub:user",
		IDP:       "stub",
		Audience:  "",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	resp, err := ts.MintForAuthorizationCode(context.Background(), code, client)
	if err != nil {
		t.Fatalf("MintForAuthorizationCode returned error: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatalf("expected access token to be minted")
	}
	if resp.RefreshToken == "" {
		t.Fatalf("expected refresh token to be issued")
	}

	claims, err := ts.ValidateAccessToken(context.Background(), resp.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken error: %v", err)
	}
	if claims.Subject != "stub:user" {
		t.Fatalf("unexpected subject: %q", claims.Subject)
	}
	if claims.ClientID != client.ClientID {
		t.Fatalf("unexpected client id: %q", claims.ClientID)
	}
	if claims.IDP != "stub" {
		t.Fatalf("unexpected idp: %q", claims.IDP)
	}
}

func TestMintForRefreshTokenRotates(t *testing.T) {
	ts, store, client := newTestTokenService(t)
	code := AuthorizationCode{
		Code:      "code",
		ClientID:  client.ClientID,
		Scope:     "openid",
		SessionID: "session",
		UserID:    "stub:user",
		IDP:       "stub",
		Audience:  "",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	resp, err := ts.MintForAuthorizationCode(context.Background(), code, client)
	if err != nil {
		t.Fatalf("mint auth code: %v", err)
	}

	refreshed, err := ts.MintForRefreshToken(context.Background(), resp.RefreshToken, client)
	if err != nil {
		t.Fatalf("MintForRefreshToken returned error: %v", err)
	}
	if refreshed.RefreshToken == resp.RefreshToken {
		t.Fatalf("expected refresh token to rotate")
	}

	if stored, ok := store.GetRefreshToken(resp.RefreshToken); !ok || !stored.Revoked {
		t.Fatalf("expected original refresh token to be marked revoked")
	}
	if _, ok := store.GetRefreshToken(refreshed.RefreshToken); !ok {
		t.Fatalf("new refresh token not stored")
	}
}

func TestMintForClientCredentials(t *testing.T) {
	ts, _, client := newTestTokenService(t)
	resp, err := ts.MintForClientCredentials(context.Background(), client, "openid", "")
	if err != nil {
		t.Fatalf("MintForClientCredentials returned error: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatalf("expected access token")
	}
	if resp.Scope != "openid" {
		t.Fatalf("scope mismatch: %q", resp.Scope)
	}
}

func TestVerifyPKCE(t *testing.T) {
	sum := sha256.Sum256([]byte("verifier"))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	code := AuthorizationCode{CodeChallenge: challenge}
	if err := verifyPKCE(code, "verifier"); err != nil {
		t.Fatalf("expected PKCE verification to pass: %v", err)
	}
	if err := verifyPKCE(code, "wrong"); err == nil {
		t.Fatalf("expected PKCE verification to fail")
	}
	if err := verifyPKCE(AuthorizationCode{}, ""); err == nil {
		t.Fatalf("expected error when verifier missing")
	}
}
