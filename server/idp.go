package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// IdentityProvider represents the minimal behaviour required from an upstream IdP.
type IdentityProvider interface {
	AuthCodeURL(state, nonce, codeChallenge, method string) string
	Exchange(ctx context.Context, code, expectedNonce string) (ProviderUser, error)
}

// OIDCProvider wraps an upstream IdP configuration and helpers.
type OIDCProvider struct {
	name        string
	oauthConfig *oauth2.Config
	verifier    *oidc.IDTokenVerifier
	logger      *slog.Logger
}

// NewOIDCProvider initializes the provider via discovery.
func NewOIDCProvider(ctx context.Context, name string, upstream UpstreamProvider, redirect string, logger *slog.Logger) (*OIDCProvider, error) {
	if upstream.Issuer == "" {
		return nil, fmt.Errorf("issuer required for provider %s", name)
	}

	issuer := upstream.Issuer
	if upstream.TenantID != "" {
		if resolved, ok := resolveAzureTenantIssuer(upstream.Issuer, upstream.TenantID); ok {
			issuer = resolved
		}
	}

	op, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover provider %s: %w", name, err)
	}

	endpoint := op.Endpoint()
	if upstream.ClientSecret == "" {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}

	oauthCfg := &oauth2.Config{
		ClientID:     upstream.ClientID,
		ClientSecret: upstream.ClientSecret,
		RedirectURL:  redirect,
		Endpoint:     endpoint,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	verifier := op.Verifier(&oidc.Config{ClientID: upstream.ClientID})

	return &OIDCProvider{
		name:        name,
		oauthConfig: oauthCfg,
		verifier:    verifier,
		logger:      logger,
	}, nil
}

// AuthCodeURL constructs the authorization request for upstream.
func (p *OIDCProvider) AuthCodeURL(state, nonce, codeChallenge, method string) string {
	opts := []oauth2.AuthCodeOption{}
	if nonce != "" {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", nonce))
	}
	if codeChallenge != "" {
		opts = append(opts,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", method),
		)
	}
	return p.oauthConfig.AuthCodeURL(state, opts...)
}

// Exchange completes the code exchange and returns a normalized user.
func (p *OIDCProvider) Exchange(ctx context.Context, code, expectedNonce string) (ProviderUser, error) {
	tok, err := p.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return ProviderUser{}, fmt.Errorf("exchange code: %w", err)
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return ProviderUser{}, fmt.Errorf("id_token missing in response")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return ProviderUser{}, fmt.Errorf("verify id_token: %w", err)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return ProviderUser{}, fmt.Errorf("parse claims: %w", err)
	}

	if expectedNonce != "" {
		if nonce, ok := claims["nonce"].(string); !ok || nonce != expectedNonce {
			return ProviderUser{}, fmt.Errorf("nonce mismatch")
		}
	}

	user := ProviderUser{
		Subject: idToken.Subject,
		Claims:  claims,
	}
	if email, ok := claims["email"].(string); ok {
		user.Email = email
	}
	if name, ok := claims["name"].(string); ok {
		user.Name = name
	} else if preferred, ok := claims["preferred_username"].(string); ok {
		user.Name = preferred
	}

	return user, nil
}

// BuildProviders prepares all configured upstream providers.
func BuildProviders(ctx context.Context, cfg Config, logger *slog.Logger) (map[string]IdentityProvider, error) {
	providers := make(map[string]IdentityProvider)

	add := func(name string, upstream UpstreamProvider) error {
		if upstream.Issuer == "" {
			return nil
		}
		redirect := strings.TrimSuffix(cfg.Server.PublicURL, "/") + "/callback/" + name
		prov, err := NewOIDCProvider(ctx, name, upstream, redirect, logger)
		if err != nil {
			return err
		}
		providers[name] = prov
		return nil
	}

	if err := add("auth0", cfg.Server.Providers.Auth0); err != nil {
		if cfg.Server.DevMode {
			logger.Warn("provider init failed", "provider", "auth0", "error", err)
		} else {
			return nil, err
		}
	}
	if err := add("entra", cfg.Server.Providers.Entra); err != nil {
		if cfg.Server.DevMode {
			logger.Warn("provider init failed", "provider", "entra", "error", err)
		} else {
			return nil, err
		}
	}

	for name, upstream := range cfg.Server.Providers.Extra {
		if err := add(name, upstream); err != nil {
			if cfg.Server.DevMode {
				logger.Warn("provider init failed", "provider", name, "error", err)
				continue
			}
			return nil, err
		}
	}

	if cfg.Server.Providers.Default != "" {
		if _, ok := providers[cfg.Server.Providers.Default]; !ok {
			if cfg.Server.DevMode {
				logger.Warn("default provider unavailable", "provider", cfg.Server.Providers.Default)
			} else {
				return nil, fmt.Errorf("default provider %s not configured", cfg.Server.Providers.Default)
			}
		}
	} else if !cfg.Server.DevMode {
		return nil, fmt.Errorf("default provider %s not configured", cfg.Server.Providers.Default)
	}

	return providers, nil
}

// ClaimsToJSON helper for debugging.
func ClaimsToJSON(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	return string(b)
}

func resolveAzureTenantIssuer(base, tenant string) (string, bool) {
	if base == "" || tenant == "" {
		return base, false
	}
	if !strings.Contains(base, "login.microsoftonline.com") {
		return base, false
	}

	trimmed := strings.TrimSuffix(base, "/")
	if strings.Contains(trimmed, "{tenant}") {
		return strings.ReplaceAll(trimmed, "{tenant}", tenant), true
	}

	const segment = "/common"
	idx := strings.Index(trimmed, segment)
	if idx == -1 {
		return base, false
	}
	prefix := trimmed[:idx]
	suffix := trimmed[idx+len(segment):]
	if len(suffix) > 0 && suffix[0] != '/' {
		suffix = "/" + suffix
	}
	return prefix + "/" + tenant + suffix, true
}
