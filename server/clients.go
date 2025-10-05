package server

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ClientRegistry holds registered OAuth clients.
type ClientRegistry struct {
	clients map[string]*Client
}

// NewClientRegistry builds the registry from configuration.
func NewClientRegistry(cfgs []ClientConfig) (*ClientRegistry, error) {
	clients := make(map[string]*Client, len(cfgs))
	for _, cfg := range cfgs {
		if cfg.ClientID == "" {
			return nil, errors.New("client_id required")
		}
		client := &Client{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURIs: cfg.RedirectURIs,
			Scopes:       cfg.Scopes,
			Audiences:    cfg.Audiences,
			Public:       cfg.ClientSecret == "",
		}
		clients[cfg.ClientID] = client
	}
	return &ClientRegistry{clients: clients}, nil
}

// Get retrieves a client definition.
func (cr *ClientRegistry) Get(id string) (*Client, bool) {
	client, ok := cr.clients[id]
	return client, ok
}

// Add registers a client in the registry (used for dev helpers).
func (cr *ClientRegistry) Add(client *Client) {
	cr.clients[client.ClientID] = client
}

// Authenticate validates client credentials (or public client PKCE use).
func (cr *ClientRegistry) Authenticate(id, secret string) (*Client, error) {
	client, ok := cr.clients[id]
	if !ok {
		return nil, fmt.Errorf("invalid_client")
	}
	if client.Public {
		return client, nil
	}
	if secret == "" || secret != client.ClientSecret {
		return nil, fmt.Errorf("invalid_client")
	}
	return client, nil
}

// ValidRedirect ensures the redirect URI is registered and safe.
// Supports "*" wildcard for internal proxy client only.
func (c *Client) ValidRedirect(uri string) bool {
	// First, validate that the URI is safe (prevent open redirects)
	if !isSafeRedirectURI(uri) {
		return false
	}

	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
		// Allow wildcard for internal proxy client
		if u == "*" && c.ClientID == "gateway-proxy" {
			return true
		}
	}
	return false
}

// isSafeRedirectURI validates that a redirect URI is safe to use
// Prevents open redirect vulnerabilities by blocking dangerous schemes and malformed URIs
func isSafeRedirectURI(uri string) bool {
	if uri == "" {
		return false
	}

	// Block dangerous URI schemes
	lower := strings.ToLower(uri)
	dangerousSchemes := []string{
		"javascript:",
		"data:",
		"file:",
		"vbscript:",
		"about:",
	}
	for _, scheme := range dangerousSchemes {
		if strings.HasPrefix(lower, scheme) {
			return false
		}
	}

	// Block protocol-relative URLs that could redirect anywhere
	if strings.HasPrefix(uri, "//") {
		return false
	}

	// Must have a proper scheme
	if !strings.Contains(uri, "://") {
		return false
	}

	// Parse the URL to validate structure
	idx := strings.Index(uri, "://")
	if idx == -1 {
		return false
	}

	scheme := uri[:idx]
	rest := uri[idx+3:]

	// Validate scheme is http or https
	if scheme != "http" && scheme != "https" {
		return false
	}

	// Check for @ symbol anywhere in the URL (blocks user:pass@host and path@domain attacks)
	if strings.Contains(rest, "@") {
		return false
	}

	// Block URLs with # in the host part (fragment identifier tricks)
	// Format: http://evil.com#http://trusted.com/callback
	if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
		hostPart := rest[:slashIdx]
		if strings.Contains(hostPart, "#") {
			return false
		}
	} else {
		// No path, check entire rest for #
		if strings.Contains(rest, "#") {
			return false
		}
	}

	return true
}

// ValidateScopes ensures requested scopes are subset of configured scopes.
func (c *Client) ValidateScopes(scope string) bool {
	if scope == "" {
		return true
	}
	req := strings.Fields(scope)
	for _, sc := range req {
		if !slices.Contains(c.Scopes, sc) {
			return false
		}
	}
	return true
}

// ResolveAudience picks audience with fallback.
func (c *Client) ResolveAudience(requested, defaultAud string) string {
	if requested != "" {
		return requested
	}
	if len(c.Audiences) > 0 {
		return c.Audiences[0]
	}
	if defaultAud != "" {
		return defaultAud
	}
	return c.ClientID
}
