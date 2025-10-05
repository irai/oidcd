package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestTokenService(t *testing.T) (*TokenService, *InMemoryStore, *Client) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Server.PublicURL = "http://gateway.test"

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewInMemoryStore()
	jwks, err := NewJWKSManager(cfg.Server.SecretsPath, logger)
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

func TestIDTokenGeneration(t *testing.T) {
	ts, store, client := newTestTokenService(t)

	// Store user profile
	store.RememberUserProfile("entra", ProviderUser{
		Subject: "user123",
		Email:   "test@example.com",
		Name:    "Test User",
	})

	code := AuthorizationCode{
		Code:      "code",
		ClientID:  client.ClientID,
		Scope:     "openid profile", // Use scopes that are allowed for the client
		SessionID: "session",
		UserID:    "entra:user123",
		IDP:       "entra",
		Nonce:     "test-nonce",
		Audience:  "",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	resp, err := ts.MintForAuthorizationCode(context.Background(), code, client)
	if err != nil {
		t.Fatalf("MintForAuthorizationCode returned error: %v", err)
	}

	// Verify ID token is present
	if resp.IDToken == "" {
		t.Fatalf("expected ID token when openid scope requested")
	}

	// Verify ID token can be parsed and contains expected claims
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, err := parser.Parse(resp.IDToken, ts.jwks.Keyfunc)
	if err != nil {
		t.Fatalf("failed to parse ID token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("expected map claims")
	}

	// Verify standard claims
	if claims["iss"] != "http://gateway.test" {
		t.Errorf("unexpected issuer: %v", claims["iss"])
	}
	if claims["sub"] != "entra:user123" {
		t.Errorf("unexpected subject: %v", claims["sub"])
	}
	if claims["aud"] != client.ClientID {
		t.Errorf("unexpected audience: %v", claims["aud"])
	}
	if claims["nonce"] != "test-nonce" {
		t.Errorf("unexpected nonce: %v", claims["nonce"])
	}

	// Verify profile claims
	if claims["email"] != "test@example.com" {
		t.Errorf("unexpected email: %v", claims["email"])
	}
	if claims["name"] != "Test User" {
		t.Errorf("unexpected name: %v", claims["name"])
	}
	if claims["preferred_username"] != "Test User" {
		t.Errorf("unexpected preferred_username: %v", claims["preferred_username"])
	}
	if claims["idp"] != "entra" {
		t.Errorf("unexpected idp: %v", claims["idp"])
	}
}

func TestIDTokenNotGeneratedWithoutOpenIDScope(t *testing.T) {
	ts, _, client := newTestTokenService(t)

	code := AuthorizationCode{
		Code:      "code",
		ClientID:  client.ClientID,
		Scope:     "profile", // No openid scope, but valid scope
		SessionID: "session",
		UserID:    "user123",
		IDP:       "entra",
		Audience:  "",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	resp, err := ts.MintForAuthorizationCode(context.Background(), code, client)
	if err != nil {
		t.Fatalf("MintForAuthorizationCode returned error: %v", err)
	}

	// ID token should not be present without openid scope
	if resp.IDToken != "" {
		t.Fatalf("ID token should not be generated without openid scope")
	}
}

func TestValidateAccessToken_MalformedToken(t *testing.T) {
	ts, _, _ := newTestTokenService(t)

	tests := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"invalid format", "not.a.jwt"},
		{"garbage", "garbage-token-data"},
		{"missing signature", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0"},
		{"invalid base64", "invalid!!!.invalid!!!.invalid!!!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ts.ValidateAccessToken(context.Background(), tt.token)
			if err == nil {
				t.Errorf("expected error for malformed token, got nil")
			}
		})
	}
}

func TestValidateAccessToken_WrongIssuer(t *testing.T) {
	ts, _, _ := newTestTokenService(t)

	// Create a token service with different issuer
	cfg := DefaultConfig()
	cfg.Server.PublicURL = "http://wrong-issuer.test"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewInMemoryStore()
	jwks, _ := NewJWKSManager(cfg.Server.SecretsPath, logger)
	wrongTS := NewTokenService(cfg, store, jwks, logger)

	client := &Client{
		ClientID:  "client",
		Scopes:    []string{"openid"},
		Audiences: []string{"api://default"},
	}

	code := AuthorizationCode{
		Code:      "code",
		ClientID:  client.ClientID,
		Scope:     "openid",
		SessionID: "session",
		UserID:    "user123",
		IDP:       "test",
		Audience:  "api://default",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	// Mint token with wrong issuer
	resp, err := wrongTS.MintForAuthorizationCode(context.Background(), code, client)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	// Try to validate with correct token service (different issuer)
	_, err = ts.ValidateAccessToken(context.Background(), resp.AccessToken)
	if err == nil {
		t.Errorf("expected error for wrong issuer, got nil")
	}
}

func TestValidateAccessToken_ExpiredToken(t *testing.T) {
	ts, _, client := newTestTokenService(t)

	// Create expired token by setting very short TTL
	oldTTL := ts.accessTTL
	ts.accessTTL = -1 * time.Hour // Already expired
	defer func() { ts.accessTTL = oldTTL }()

	code := AuthorizationCode{
		Code:      "code",
		ClientID:  client.ClientID,
		Scope:     "openid",
		SessionID: "session",
		UserID:    "user123",
		IDP:       "test",
		Audience:  "api://default",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	resp, err := ts.MintForAuthorizationCode(context.Background(), code, client)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	// Try to validate expired token
	_, err = ts.ValidateAccessToken(context.Background(), resp.AccessToken)
	if err == nil {
		t.Errorf("expected error for expired token, got nil")
	}
}

func TestRefreshToken_Revoked(t *testing.T) {
	ts, store, client := newTestTokenService(t)

	code := AuthorizationCode{
		Code:      "code",
		ClientID:  client.ClientID,
		Scope:     "openid",
		SessionID: "session",
		UserID:    "user123",
		IDP:       "test",
		Audience:  "",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	resp, err := ts.MintForAuthorizationCode(context.Background(), code, client)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	// Manually revoke the refresh token
	if rt, ok := store.GetRefreshToken(resp.RefreshToken); ok {
		rt.Revoked = true
		store.mu.Lock()
		store.refreshTokens[rt.ID] = rt
		store.mu.Unlock()
	}

	// Try to use revoked refresh token
	_, err = ts.MintForRefreshToken(context.Background(), resp.RefreshToken, client)
	if err == nil {
		t.Errorf("expected error for revoked refresh token, got nil")
	}
}

func TestRefreshToken_InvalidToken(t *testing.T) {
	ts, _, client := newTestTokenService(t)

	tests := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"non-existent token", "does-not-exist"},
		{"random garbage", "abc123xyz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ts.MintForRefreshToken(context.Background(), tt.token, client)
			if err == nil {
				t.Errorf("expected error for invalid refresh token, got nil")
			}
		})
	}
}

func TestRefreshToken_ClientMismatch(t *testing.T) {
	ts, _, client := newTestTokenService(t)

	code := AuthorizationCode{
		Code:      "code",
		ClientID:  client.ClientID,
		Scope:     "openid",
		SessionID: "session",
		UserID:    "user123",
		IDP:       "test",
		Audience:  "",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	resp, err := ts.MintForAuthorizationCode(context.Background(), code, client)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	// Try to use refresh token with different client
	differentClient := &Client{
		ClientID:  "different-client",
		Scopes:    []string{"openid"},
		Audiences: []string{"api://default"},
	}

	_, err = ts.MintForRefreshToken(context.Background(), resp.RefreshToken, differentClient)
	if err == nil {
		t.Errorf("expected error for client mismatch, got nil")
	}
}

func TestPKCE_MalformedChallenge(t *testing.T) {
	tests := []struct {
		name      string
		challenge string
		verifier  string
	}{
		{"invalid base64", "not-valid-base64!!!", "verifier"},
		{"too short", "abc", "verifier"},
		{"empty challenge", "", "verifier"},
		{"SQL injection attempt", "'; DROP TABLE users; --", "verifier"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := AuthorizationCode{CodeChallenge: tt.challenge}
			err := verifyPKCE(code, tt.verifier)
			if err == nil {
				t.Errorf("expected error for malformed challenge, got nil")
			}
		})
	}
}

func TestTokenRevocation(t *testing.T) {
	ts, store, client := newTestTokenService(t)

	code := AuthorizationCode{
		Code:      "code",
		ClientID:  client.ClientID,
		Scope:     "openid",
		SessionID: "session",
		UserID:    "user123",
		IDP:       "test",
		Audience:  "api://default",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	resp, err := ts.MintForAuthorizationCode(context.Background(), code, client)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	// Validate token works before revocation
	claims, err := ts.ValidateAccessToken(context.Background(), resp.AccessToken)
	if err != nil {
		t.Fatalf("token validation failed: %v", err)
	}

	// Revoke the access token
	ts.Revoke(context.Background(), client, resp.AccessToken)

	// Verify the JTI is blacklisted
	if !store.JTIBlacklisted(claims.ID) {
		t.Errorf("expected JTI to be blacklisted after revocation")
	}

	// Token should still parse but be marked as invalid in a real system
	// (Note: Current implementation may not enforce blacklist in ValidateAccessToken)
}

func TestInvalidScope(t *testing.T) {
	ts, _, _ := newTestTokenService(t)

	client := &Client{
		ClientID:  "client",
		Scopes:    []string{"openid", "profile"},
		Audiences: []string{"api://default"},
	}

	code := AuthorizationCode{
		Code:      "code",
		ClientID:  client.ClientID,
		Scope:     "openid profile admin", // "admin" not allowed
		SessionID: "session",
		UserID:    "user123",
		IDP:       "test",
		Audience:  "",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	_, err := ts.MintForAuthorizationCode(context.Background(), code, client)
	if err == nil {
		t.Errorf("expected error for invalid scope, got nil")
	}
}

func TestUserProfileWithoutEmail(t *testing.T) {
	ts, store, client := newTestTokenService(t)

	// Store user profile without email
	store.RememberUserProfile("local", ProviderUser{
		Subject: "user456",
		Name:    "Name Only User",
		// Email is empty
	})

	code := AuthorizationCode{
		Code:      "code",
		ClientID:  client.ClientID,
		Scope:     "openid profile",
		SessionID: "session",
		UserID:    "local:user456",
		IDP:       "local",
		Nonce:     "nonce",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	resp, err := ts.MintForAuthorizationCode(context.Background(), code, client)
	if err != nil {
		t.Fatalf("MintForAuthorizationCode failed: %v", err)
	}

	// Parse ID token
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, err := parser.Parse(resp.IDToken, ts.jwks.Keyfunc)
	if err != nil {
		t.Fatalf("failed to parse ID token: %v", err)
	}

	claims := token.Claims.(jwt.MapClaims)

	// Email should not be present
	if _, hasEmail := claims["email"]; hasEmail {
		t.Errorf("email claim should not be present when user has no email")
	}

	// Name should be present
	if claims["name"] != "Name Only User" {
		t.Errorf("unexpected name: %v", claims["name"])
	}
}

func TestUserProfileNotFound(t *testing.T) {
	ts, _, client := newTestTokenService(t)

	// Don't store any user profile

	code := AuthorizationCode{
		Code:      "code",
		ClientID:  client.ClientID,
		Scope:     "openid profile",
		SessionID: "session",
		UserID:    "unknown:user",
		IDP:       "unknown",
		Nonce:     "nonce",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	resp, err := ts.MintForAuthorizationCode(context.Background(), code, client)
	if err != nil {
		t.Fatalf("MintForAuthorizationCode failed: %v", err)
	}

	// Parse ID token
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, err := parser.Parse(resp.IDToken, ts.jwks.Keyfunc)
	if err != nil {
		t.Fatalf("failed to parse ID token: %v", err)
	}

	claims := token.Claims.(jwt.MapClaims)

	// Profile claims should not be present
	if _, hasEmail := claims["email"]; hasEmail {
		t.Errorf("email should not be present for unknown user")
	}
	if _, hasName := claims["name"]; hasName {
		t.Errorf("name should not be present for unknown user")
	}

	// Standard claims should still be present
	if claims["sub"] != "unknown:user" {
		t.Errorf("unexpected subject: %v", claims["sub"])
	}
}
