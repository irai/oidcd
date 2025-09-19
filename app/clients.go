package app

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

// ValidRedirect ensures the redirect URI is registered.
func (c *Client) ValidRedirect(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
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
