package server

import (
	"bytes"
	"errors"
	"fmt"
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
		if err := yaml.Unmarshal(sanitized, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse config: %w", err)
		}
	}

	applyEnvOverrides(&cfg)

	if err := cfg.Validate(); err != nil {
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
		return errors.New("server.public_url is required")
	}
	if !c.Server.DevMode && len(c.Server.TLS.Domains) == 0 {
		return errors.New("server.tls.domains must be provided in production")
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
			return fmt.Errorf("server.cookie_domain '%s' does not match server.public_url domain '%s'", c.Server.CookieDomain, publicURL)
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
		return errors.New("at least one OAuth2 client must be configured (unless using proxy-only mode)")
	}

	if !c.Server.DevMode && c.Server.Providers.Default == "" {
		return errors.New("server.providers.default is required")
	}
	return nil
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
