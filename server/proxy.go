package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// ProxyManager handles reverse proxy routing based on Host header.
type ProxyManager struct {
	routes    map[string]*proxyRoute
	validator *TokenService
	logger    *slog.Logger
}

type proxyRoute struct {
	host           string
	proxy          *httputil.ReverseProxy
	requireAuth    bool
	requiredScopes []string
	stripPrefix    string
}

// NewProxyManager creates a proxy manager from configuration.
func NewProxyManager(cfg ProxyConfig, validator *TokenService, logger *slog.Logger) (*ProxyManager, error) {
	pm := &ProxyManager{
		routes:    make(map[string]*proxyRoute),
		validator: validator,
		logger:    logger,
	}

	for _, routeCfg := range cfg.Routes {
		if err := pm.addRoute(routeCfg); err != nil {
			return nil, fmt.Errorf("invalid proxy route for %s: %w", routeCfg.Host, err)
		}
	}

	return pm, nil
}

func (pm *ProxyManager) addRoute(cfg ProxyRoute) error {
	if cfg.Host == "" {
		return fmt.Errorf("host is required")
	}
	if cfg.Target == "" {
		return fmt.Errorf("target is required")
	}

	targetURL, err := url.Parse(cfg.Target)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	timeout := 30 * time.Second
	if cfg.Timeout != "" {
		parsed, err := time.ParseDuration(cfg.Timeout)
		if err != nil {
			return fmt.Errorf("invalid timeout: %w", err)
		}
		timeout = parsed
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = transport

	// Custom director to handle host headers and path stripping
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Strip prefix if configured
		if cfg.StripPrefix != "" && strings.HasPrefix(req.URL.Path, cfg.StripPrefix) {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, cfg.StripPrefix)
			if req.URL.Path == "" {
				req.URL.Path = "/"
			}
		}

		// Preserve original Host header if configured
		if !cfg.PreserveHost {
			req.Host = targetURL.Host
		}

		// Set standard proxy headers
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			prior := req.Header.Get("X-Forwarded-For")
			if prior != "" {
				clientIP = prior + ", " + clientIP
			}
			req.Header.Set("X-Forwarded-For", clientIP)
		}
		req.Header.Set("X-Forwarded-Proto", schemeFromRequest(req))
		req.Header.Set("X-Forwarded-Host", req.Host)
	}

	// Custom error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		pm.logger.Error("proxy error",
			"host", cfg.Host,
			"target", cfg.Target,
			"error", err,
			"path", r.URL.Path,
		)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	route := &proxyRoute{
		host:           strings.ToLower(cfg.Host),
		proxy:          proxy,
		requireAuth:    cfg.RequireAuth,
		requiredScopes: cfg.RequiredScopes,
		stripPrefix:    cfg.StripPrefix,
	}

	pm.routes[route.host] = route
	pm.logger.Info("proxy route added",
		"host", cfg.Host,
		"target", cfg.Target,
		"require_auth", cfg.RequireAuth,
		"scopes", cfg.RequiredScopes,
	)

	return nil
}

// ServeHTTP handles incoming requests and routes them based on Host header.
func (pm *ProxyManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(strings.Split(r.Host, ":")[0])

	route, ok := pm.routes[host]
	if !ok {
		pm.logger.Debug("no proxy route for host", "host", host, "path", r.URL.Path)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Check authentication if required
	if route.requireAuth {
		token := extractBearerToken(r.Header.Get("Authorization"))
		if token == "" {
			pm.logger.Debug("missing auth token", "host", host, "path", r.URL.Path)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims, err := pm.validator.ValidateAccessToken(r.Context(), token)
		if err != nil {
			pm.logger.Debug("invalid auth token", "host", host, "path", r.URL.Path, "error", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check required scopes
		if len(route.requiredScopes) > 0 {
			if !hasRequiredScopes(claims.Scope, route.requiredScopes) {
				pm.logger.Debug("insufficient scopes",
					"host", host,
					"path", r.URL.Path,
					"required", route.requiredScopes,
					"provided", claims.Scope,
				)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		// Add claims to context for downstream use
		ctx := context.WithValue(r.Context(), "claims", claims)
		r = r.WithContext(ctx)
	}

	pm.logger.Debug("proxying request",
		"host", host,
		"path", r.URL.Path,
		"method", r.Method,
	)

	route.proxy.ServeHTTP(w, r)
}

func hasRequiredScopes(provided string, required []string) bool {
	providedScopes := strings.Fields(provided)
	scopeMap := make(map[string]bool, len(providedScopes))
	for _, s := range providedScopes {
		scopeMap[s] = true
	}
	for _, req := range required {
		if !scopeMap[req] {
			return false
		}
	}
	return true
}

func schemeFromRequest(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}
