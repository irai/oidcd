package server

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Hardcoded token and session defaults
const (
	DefaultAccessTTL     = 10 * time.Minute
	DefaultRefreshTTL    = 24 * time.Hour
	DefaultSessionTTL    = 12 * time.Hour
	DefaultRotateRefresh = true
)

// Hardcoded CORS defaults
var (
	DefaultCORSAllowedHeaders = []string{"Authorization", "Content-Type"}
	DefaultCORSAllowedMethods = []string{"GET", "POST", "OPTIONS"}
)

// Config captures the full application configuration loaded from YAML and environment variables.
type Config struct {
	Server        ServerConfig   `yaml:"server"`
	OAuth2Clients []ClientConfig `yaml:"oauth2_clients"`
	Proxy         ProxyConfig    `yaml:"proxy"`
}

// ServerConfig controls listener, TLS, and HTTP concerns.
type ServerConfig struct {
	PublicURL         string         `yaml:"public_url"`
	DevListenAddr     string         `yaml:"dev_listen_addr"`
	HTTPListenAddr    string         `yaml:"http_listen_addr"`
	HTTPSListenAddr   string         `yaml:"https_listen_addr"`
	DevMode           bool           `yaml:"dev_mode"`
	CookieDomain      string         `yaml:"cookie_domain"`
	SecretsPath       string         `yaml:"secrets_path"`
	ServerID          string         `yaml:"server_id"`
	TLS               TLSConfig      `yaml:"tls"`
	TrustProxyHeaders bool           `yaml:"trust_proxy_headers"`
	Providers         ProviderConfig `yaml:"providers"`
}

// TLSConfig defines autocert behaviour and TLS constraints.
type TLSConfig struct {
	Domains    []string `yaml:"domains"`
	Email      string   `yaml:"email"`
	MinVersion string   `yaml:"min_version"`
}

// ClientConfig describes an OAuth client.
type ClientConfig struct {
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	RedirectURIs []string `yaml:"redirect_uris"`
	Scopes       []string `yaml:"scopes"`
	Audiences    []string `yaml:"audiences"`
}

// ProviderConfig groups upstream providers.
type ProviderConfig struct {
	Default string                      `yaml:"default"`
	Auth0   UpstreamProvider            `yaml:"auth0"`
	Entra   UpstreamProvider            `yaml:"entra"`
	Extra   map[string]UpstreamProvider `yaml:"extra"`
}

// UpstreamProvider encapsulates issuer and credentials for an upstream IdP.
type UpstreamProvider struct {
	Issuer       string `yaml:"issuer"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	TenantID     string `yaml:"tenant_id"`
}

// ProxyConfig defines reverse proxy routes for host-based routing.
type ProxyConfig struct {
	Routes []ProxyRoute `yaml:"routes"`
}

// ProxyRoute maps a hostname to a backend target.
type ProxyRoute struct {
	Host               string   `yaml:"host"`
	Target             string   `yaml:"target"`
	RequireAuth        bool     `yaml:"require_auth"`
	RequiredScopes     []string `yaml:"required_scopes"`
	StripPrefix        string   `yaml:"strip_prefix"`
	PreserveHost       bool     `yaml:"preserve_host"`
	Timeout            string   `yaml:"timeout"`
	InsecureSkipVerify bool     `yaml:"insecure_skip_verify"`

	// Enhanced authentication and JWT injection
	InjectJWT        bool              `yaml:"inject_jwt"`
	JWTHeaderName    string            `yaml:"jwt_header_name"`
	InjectUserClaims bool              `yaml:"inject_user_claims"`
	ClaimsHeaders    map[string]string `yaml:"claims_headers"`
	SkipPaths        []string          `yaml:"skip_paths"`
	AuthRedirectURL  string            `yaml:"auth_redirect_url"`
	InjectAsBearer   bool              `yaml:"inject_as_bearer"`
}

// LoadConfig reads the YAML config file and merges environment overrides.
func LoadConfig(path string) (Config, error) {
	cfg := defaultConfig()

	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("read config: %w", err)
		}
		sanitized := stripYAMLComments(b)

		// Use strict unmarshaling to detect unknown fields
		decoder := yaml.NewDecoder(bytes.NewReader(sanitized))
		decoder.KnownFields(true)

		if err := decoder.Decode(&cfg); err != nil {
			// Check if it's an unknown field error
			if strings.Contains(err.Error(), "field") && strings.Contains(err.Error(), "not found") {
				slog.Error("Configuration contains unknown keys", "error", err, "file", path)
				return Config{}, fmt.Errorf("invalid config: %w (check for typos or deprecated fields)", err)
			}
			slog.Error("Failed to parse configuration", "error", err, "file", path)
			return Config{}, fmt.Errorf("parse config: %w", err)
		}
	}

	applyEnvOverrides(&cfg)

	if err := cfg.Validate(); err != nil {
		slog.Error("Configuration validation failed", "error", err)
		return Config{}, err
	}

	return cfg, nil
}

func defaultConfig() Config {
	return Config{
		Server: ServerConfig{
			PublicURL:       "http://127.0.0.1:8080",
			DevListenAddr:   "127.0.0.1:8080",
			HTTPListenAddr:  ":80",
			HTTPSListenAddr: ":443",
			DevMode:         true,
			SecretsPath:     ".secrets",
			ServerID:        "oidcd",
			TLS: TLSConfig{
				Domains:    []string{"localhost"},
				Email:      "",
				MinVersion: "1.2",
			},
			Providers: ProviderConfig{
				Entra: UpstreamProvider{
					Issuer: "https://login.microsoftonline.com/common/v2.0",
				},
			},
		},
	}
}

// DefaultConfig returns the default configuration template.
func DefaultConfig() Config {
	return defaultConfig()
}

func stripYAMLComments(in []byte) []byte {
	lines := bytes.Split(in, []byte("\n"))
	out := make([][]byte, 0, len(lines))
	for _, line := range lines {
		trim := bytes.TrimLeft(line, " \t")
		if len(trim) > 0 && trim[0] == '#' {
			continue
		}
		out = append(out, line)
	}
	return bytes.Join(out, []byte("\n"))
}

func applyEnvOverrides(cfg *Config) {
	overrides := map[string]func(string){
		"OIDCD_SERVER_PUBLIC_URL":        func(v string) { cfg.Server.PublicURL = v },
		"OIDCD_SERVER_DEV_LISTEN_ADDR":   func(v string) { cfg.Server.DevListenAddr = v },
		"OIDCD_SERVER_HTTP_LISTEN_ADDR":  func(v string) { cfg.Server.HTTPListenAddr = v },
		"OIDCD_SERVER_HTTPS_LISTEN_ADDR": func(v string) { cfg.Server.HTTPSListenAddr = v },
		"OIDCD_SERVER_DEV_MODE":          func(v string) { cfg.Server.DevMode = parseBool(v, cfg.Server.DevMode) },
		"OIDCD_SERVER_TLS_DOMAINS":       func(v string) { cfg.Server.TLS.Domains = splitAndTrim(v) },
		"OIDCD_SERVER_TLS_EMAIL":         func(v string) { cfg.Server.TLS.Email = v },
		"OIDCD_SERVER_SECRETS_PATH":      func(v string) { cfg.Server.SecretsPath = v },
		"OIDCD_SERVER_ID":                func(v string) { cfg.Server.ServerID = v },
	}

	for key, fn := range overrides {
		if val, ok := os.LookupEnv(key); ok {
			fn(val)
		}
	}
}

func parseDuration(val string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(val)
	if err != nil {
		return fallback
	}
	return d
}

func parseBool(val string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func splitAndTrim(val string) []string {
	parts := strings.Split(val, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Validate performs minimal sanity checks on the config.
func (c Config) Validate() error {
	if c.Server.PublicURL == "" {
		slog.Error("Missing required configuration", "field", "server.public_url")
		return errors.New("server.public_url is required")
	}

	// Validate server.public_url format
	if !strings.HasPrefix(c.Server.PublicURL, "http://") && !strings.HasPrefix(c.Server.PublicURL, "https://") {
		slog.Error("Invalid configuration value", "field", "server.public_url", "value", c.Server.PublicURL, "reason", "must start with http:// or https://")
		return fmt.Errorf("server.public_url must start with http:// or https://, got: %s", c.Server.PublicURL)
	}

	if !c.Server.DevMode && len(c.Server.TLS.Domains) == 0 {
		slog.Error("Missing required configuration for production mode", "field", "server.tls.domains")
		return errors.New("server.tls.domains must be provided in production")
	}

	// Validate TLS minimum version
	if c.Server.TLS.MinVersion != "" {
		validVersions := map[string]bool{"1.2": true, "1.3": true}
		if !validVersions[c.Server.TLS.MinVersion] {
			slog.Error("Invalid TLS minimum version", "field", "server.tls.min_version", "value", c.Server.TLS.MinVersion, "valid_values", []string{"1.2", "1.3"})
			return fmt.Errorf("server.tls.min_version must be '1.2' or '1.3', got: %s", c.Server.TLS.MinVersion)
		}
	}

	// Validate cookie_domain matches public_url domain
	if c.Server.CookieDomain != "" {
		// Extract domain from public_url
		publicURL := strings.TrimPrefix(c.Server.PublicURL, "http://")
		publicURL = strings.TrimPrefix(publicURL, "https://")

		// Remove port if present
		if idx := strings.Index(publicURL, ":"); idx != -1 {
			publicURL = publicURL[:idx]
		}

		// Remove path if present
		if idx := strings.Index(publicURL, "/"); idx != -1 {
			publicURL = publicURL[:idx]
		}

		// Cookie domain should be a suffix of the public URL domain
		// e.g., public_url: gw.dev.nexxia.com.au -> cookie_domain: .dev.nexxia.com.au (valid)
		cookieDomain := strings.TrimPrefix(c.Server.CookieDomain, ".")
		if !strings.HasSuffix(publicURL, cookieDomain) {
			slog.Error("Cookie domain mismatch",
				"field", "server.cookie_domain",
				"cookie_domain", c.Server.CookieDomain,
				"public_url_domain", publicURL,
				"reason", "cookie_domain must be a suffix of public_url domain")
			return fmt.Errorf("server.cookie_domain '%s' does not match server.public_url domain '%s'", c.Server.CookieDomain, publicURL)
		}
	}

	// Validate OAuth2 client configurations
	for i, client := range c.OAuth2Clients {
		if client.ClientID == "" {
			slog.Error("OAuth2 client missing client_id", "index", i)
			return fmt.Errorf("oauth2_clients[%d]: client_id is required", i)
		}
		if len(client.RedirectURIs) == 0 {
			slog.Error("OAuth2 client missing redirect URIs", "client_id", client.ClientID, "index", i)
			return fmt.Errorf("oauth2_clients[%d] (%s): at least one redirect_uri is required", i, client.ClientID)
		}
		// Validate redirect URIs format
		for j, uri := range client.RedirectURIs {
			if !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://") {
				slog.Error("Invalid redirect URI", "client_id", client.ClientID, "redirect_uri", uri, "index", j, "reason", "must be a valid HTTP(S) URL")
				return fmt.Errorf("oauth2_clients[%d] (%s): redirect_uris[%d] must start with http:// or https://, got: %s", i, client.ClientID, j, uri)
			}
		}
	}

	// Validate proxy routes
	for i, route := range c.Proxy.Routes {
		if route.Host == "" {
			slog.Error("Proxy route missing host", "index", i)
			return fmt.Errorf("proxy.routes[%d]: host is required", i)
		}
		if route.Target == "" {
			slog.Error("Proxy route missing target", "host", route.Host, "index", i)
			return fmt.Errorf("proxy.routes[%d] (%s): target is required", i, route.Host)
		}
		// Validate target URL format
		if !strings.HasPrefix(route.Target, "http://") && !strings.HasPrefix(route.Target, "https://") {
			slog.Error("Invalid proxy target URL", "host", route.Host, "target", route.Target, "reason", "must be a valid HTTP(S) URL")
			return fmt.Errorf("proxy.routes[%d] (%s): target must start with http:// or https://, got: %s", i, route.Host, route.Target)
		}
		// Validate timeout if specified
		if route.Timeout != "" {
			if _, err := time.ParseDuration(route.Timeout); err != nil {
				slog.Error("Invalid proxy route timeout", "host", route.Host, "timeout", route.Timeout, "error", err)
				return fmt.Errorf("proxy.routes[%d] (%s): invalid timeout duration '%s': %w", i, route.Host, route.Timeout, err)
			}
		}
	}

	// Check if proxy mode requires authentication
	hasAuthProxyRoutes := false
	for _, route := range c.Proxy.Routes {
		if route.RequireAuth {
			hasAuthProxyRoutes = true
			break
		}
	}

	// OAuth2 clients are only required if not using proxy-only mode
	// Proxy mode uses session cookies, not OAuth2 flows
	if len(c.OAuth2Clients) == 0 && !hasAuthProxyRoutes {
		slog.Error("No OAuth2 clients configured", "reason", "at least one OAuth2 client must be configured unless using proxy-only mode")
		return errors.New("at least one OAuth2 client must be configured (unless using proxy-only mode)")
	}

	if !c.Server.DevMode && c.Server.Providers.Default == "" {
		slog.Error("Missing required provider configuration", "field", "server.providers.default", "reason", "required in production mode")
		return errors.New("server.providers.default is required in production mode")
	}

	// Validate that the default provider is actually configured
	if c.Server.Providers.Default != "" {
		provider := c.getProvider(c.Server.Providers.Default)
		if provider == nil {
			slog.Error("Default provider not found", "default_provider", c.Server.Providers.Default, "available", []string{"auth0", "entra"})
			return fmt.Errorf("server.providers.default '%s' is not configured (check providers.auth0, providers.entra, or providers.extra)", c.Server.Providers.Default)
		}
		if provider.Issuer == "" {
			slog.Error("Provider missing issuer", "provider", c.Server.Providers.Default, "field", fmt.Sprintf("server.providers.%s.issuer", c.Server.Providers.Default))
			return fmt.Errorf("server.providers.%s.issuer is required", c.Server.Providers.Default)
		}
		if provider.ClientID == "" {
			slog.Error("Provider missing client_id", "provider", c.Server.Providers.Default, "field", fmt.Sprintf("server.providers.%s.client_id", c.Server.Providers.Default))
			return fmt.Errorf("server.providers.%s.client_id is required", c.Server.Providers.Default)
		}
	}

	return nil
}

// getProvider retrieves a provider by name
func (c Config) getProvider(name string) *UpstreamProvider {
	switch name {
	case "auth0":
		return &c.Server.Providers.Auth0
	case "entra":
		return &c.Server.Providers.Entra
	default:
		if p, ok := c.Server.Providers.Extra[name]; ok {
			return &p
		}
		return nil
	}
}

// InferCORSOrigins extracts allowed origins from OAuth2 client redirect URIs and proxy targets
func (c Config) InferCORSOrigins() []string {
	seen := make(map[string]bool)
	origins := []string{}

	// Extract origins from OAuth2 client redirect URIs
	for _, client := range c.OAuth2Clients {
		for _, redirectURI := range client.RedirectURIs {
			if origin := extractOrigin(redirectURI); origin != "" && !seen[origin] {
				seen[origin] = true
				origins = append(origins, origin)
			}
		}
	}

	// Extract origins from proxy target URLs
	for _, route := range c.Proxy.Routes {
		if origin := extractOrigin(route.Target); origin != "" && !seen[origin] {
			seen[origin] = true
			origins = append(origins, origin)
		}
	}

	return origins
}

// extractOrigin extracts the origin (scheme://host:port) from a URL
func extractOrigin(urlStr string) string {
	if urlStr == "" || urlStr == "*" {
		return ""
	}

	// Parse the URL
	u, err := parseURL(urlStr)
	if err != nil {
		return ""
	}

	// Build origin from scheme and host
	if u.Scheme == "" || u.Host == "" {
		return ""
	}

	return u.Scheme + "://" + u.Host
}

// parseURL is a helper to parse URLs
func parseURL(rawURL string) (*struct{ Scheme, Host string }, error) {
	// Simple URL parsing to extract scheme and host
	scheme := ""
	host := ""

	// Remove scheme
	if idx := strings.Index(rawURL, "://"); idx != -1 {
		scheme = rawURL[:idx]
		rawURL = rawURL[idx+3:]
	} else {
		return nil, fmt.Errorf("invalid URL: missing scheme")
	}

	// Extract host (everything before first /)
	if idx := strings.Index(rawURL, "/"); idx != -1 {
		host = rawURL[:idx]
	} else {
		host = rawURL
	}

	return &struct{ Scheme, Host string }{scheme, host}, nil
}
