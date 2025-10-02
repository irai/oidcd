package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ProxyManager handles reverse proxy routing based on Host header.
type ProxyManager struct {
	routes         map[string]*proxyRoute
	validator      *TokenService
	sessionManager *SessionManager
	store          *InMemoryStore
	logger         *slog.Logger
	gatewayIssuer  string
}

type proxyRoute struct {
	host           string
	proxy          *httputil.ReverseProxy
	requireAuth    bool
	requiredScopes []string
	stripPrefix    string

	// Enhanced authentication and JWT injection
	injectJWT        bool
	jwtHeaderName    string
	injectUserClaims bool
	claimsHeaders    map[string]string
	skipPaths        []string
	authRedirectURL  string
	injectAsBearer   bool
}

// AuthResult represents the result of authentication validation
type AuthResult struct {
	Claims    *AccessTokenClaims
	Session   *Session
	TokenType string // "bearer" or "cookie"
	UserID    string
	Scopes    []string
	UserInfo  *UserInfo
}

// AuthRedirect stores information about redirect after authentication
type AuthRedirect struct {
	OriginalURL string
	RedirectURI string
	ExpiresAt   time.Time
}

// NewProxyManager creates a proxy manager from configuration.
func NewProxyManager(cfg ProxyConfig, validator *TokenService, sessionManager *SessionManager, store *InMemoryStore, gatewayIssuer string, logger *slog.Logger) (*ProxyManager, error) {
	pm := &ProxyManager{
		routes:         make(map[string]*proxyRoute),
		validator:      validator,
		sessionManager: sessionManager,
		store:          store,
		logger:         logger,
		gatewayIssuer:  strings.TrimSuffix(gatewayIssuer, "/"),
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
		req.Header.Set("X-Forwarded-Proto", pm.schemeFromRequest(req))
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
		host:             strings.ToLower(cfg.Host),
		proxy:            proxy,
		requireAuth:      cfg.RequireAuth,
		requiredScopes:   cfg.RequiredScopes,
		stripPrefix:      cfg.StripPrefix,
		injectJWT:        cfg.InjectJWT || cfg.RequireAuth, // Default to true if auth required
		jwtHeaderName:    cfg.JWTHeaderName,
		injectUserClaims: cfg.InjectUserClaims || cfg.RequireAuth, // Default to true if auth required
		claimsHeaders:    cfg.ClaimsHeaders,
		skipPaths:        cfg.SkipPaths,
		authRedirectURL:  cfg.AuthRedirectURL,
		injectAsBearer:   cfg.InjectAsBearer,
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

	// Check if this is an OAuth callback (has authorization code)
	if code := r.URL.Query().Get("code"); code != "" && r.URL.Query().Get("state") != "" {
		pm.handleOAuthCallback(w, r, route)
		return
	}

	// Skip authentication for excluded paths (health checks, static assets)
	if pm.shouldSkipAuth(route, r.URL.Path) {
		pm.proxyRequest(w, r, route, nil)
		return
	}

	// Perform authentication and authorization if required
	var authResult *AuthResult
	var err error

	if route.requireAuth {
		authResult, err = pm.authenticateRequest(r, route)
		if err != nil {
			pm.handleAuthError(w, r, route, err)
			return
		}

		// Inject JWT and user claims into the forwarded request
		pm.enhanceRequestWithAuth(r, route, authResult)
	}

	// Forward to upstream service
	pm.proxyRequest(w, r, route, authResult)
}

// authenticateRequest performs intelligent authentication detection
func (pm *ProxyManager) authenticateRequest(r *http.Request, route *proxyRoute) (*AuthResult, error) {
	// Try multiple authentication methods

	// 1. Bearer Token Authentication
	if authResult := pm.tryBearerAuth(r); authResult != nil {
		// Validate scopes
		if err := pm.validateScopes(authResult.Scopes, route.requiredScopes); err != nil {
			return nil, fmt.Errorf("insufficient scopes: %w", err)
		}
		return authResult, nil
	}

	// 2. Cookie-based Authentication
	if authResult := pm.tryCookieAuth(r); authResult != nil {
		// Create access token from session for injection
		tokenClaims, err := pm.sessionToAccessToken(authResult.Session, route.host)
		if err != nil {
			return nil, fmt.Errorf("create access token: %w", err)
		}
		authResult.Claims = tokenClaims

		// Check scopes
		if err := pm.validateScopes(authResult.Scopes, route.requiredScopes); err != nil {
			return nil, fmt.Errorf("insufficient scopes: %w", err)
		}
		return authResult, nil
	}

	return nil, fmt.Errorf("no valid authentication found")
}

// tryBearerAuth attempts to authenticate using Bearer token
func (pm *ProxyManager) tryBearerAuth(r *http.Request) *AuthResult {
	token := extractBearerToken(r.Header.Get("Authorization"))
	if token == "" {
		return nil
	}

	claims, err := pm.validator.ValidateAccessToken(r.Context(), token)
	if err != nil {
		pm.logger.Debug("bearer token validation failed", "error", err)
		return nil
	}

	scopes := strings.Fields(claims.Scope)
	return &AuthResult{
		Claims:    claims,
		TokenType: "bearer",
		UserID:    claims.Subject,
		Scopes:    scopes,
	}
}

// tryCookieAuth attempts to authenticate using session cookies
func (pm *ProxyManager) tryCookieAuth(r *http.Request) *AuthResult {
	session, err := pm.sessionManager.Fetch(r)
	if err != nil || session == nil {
		return nil
	}

	return &AuthResult{
		Session:   session,
		TokenType: "cookie",
		UserID:    session.UserID,
		Scopes:    []string{"gateway.authenticated"}, // Default scope for cookie auth
	}
}

// validateScopes checks if user has required scopes
func (pm *ProxyManager) validateScopes(userScopes []string, required []string) error {
	if len(required) == 0 {
		return nil // No specific scope requirements
	}

	if !hasRequiredScopesFromSlice(userScopes, required) {
		return fmt.Errorf("user has scopes %v, required %v", userScopes, required)
	}

	return nil
}

func hasRequiredScopesFromSlice(userScopes []string, required []string) bool {
	scopeMap := make(map[string]bool, len(userScopes))
	for _, s := range userScopes {
		scopeMap[s] = true
	}
	for _, req := range required {
		if !scopeMap[req] {
			return false
		}
	}
	return true
}

func hasRequiredScopes(provided string, required []string) bool {
	providedScopes := strings.Fields(provided)
	return hasRequiredScopesFromSlice(providedScopes, required)
}

// sessionToAccessToken converts a session to access token claims
func (pm *ProxyManager) sessionToAccessToken(session *Session, targetHost string) (*AccessTokenClaims, error) {
	// Parse user ID to get original subject (format: "provider:subject")
	parts := strings.Split(session.UserID, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid user ID format: %s", session.UserID)
	}

	claims := &AccessTokenClaims{
		Scope:    "gateway.authenticated proxy.access",
		ClientID: "gateway-proxy",
		IDP:      session.IDP,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   session.UserID,
			Issuer:    pm.gatewayIssuer,
			Audience:  []string{targetHost, "proxy"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			ID:        pm.generateJTI(),
		},
	}

	return claims, nil
}

// generateJTI generates a unique JWT ID
func (pm *ProxyManager) generateJTI() string {
	return fmt.Sprintf("proxy_%d", time.Now().UnixNano())
}

// enhanceRequestWithAuth injects JWT and user claims into the forwarded request
func (pm *ProxyManager) enhanceRequestWithAuth(r *http.Request, route *proxyRoute, auth *AuthResult) {
	if !route.injectJWT && !route.injectUserClaims {
		return // No injection required
	}

	if route.injectJWT && auth.Claims != nil {
		// Create and inject JWT token for the downstream service
		jwtToken, err := pm.createProxyJWT(auth, route.host)
		if err == nil {
			headerName := route.jwtHeaderName
			if headerName == "" {
				headerName = "X-Auth-Token" // Simple default
			}
			r.Header.Set(headerName, jwtToken)

			// Also inject as standard Authorization header if configured
			if route.injectAsBearer {
				r.Header.Set("Authorization", "Bearer "+jwtToken)
			}
		}
	}

	if route.injectUserClaims {
		pm.injectUserClaimsAsHeaders(r, auth, route.claimsHeaders)
	}

	// Add standard user identification headers
	r.Header.Set("X-User-ID", auth.UserID)
	r.Header.Set("X-Auth-Type", auth.TokenType)
	if len(auth.Scopes) > 0 {
		r.Header.Set("X-User-Scopes", strings.Join(auth.Scopes, " "))
	}
}

// createProxyJWT creates a new JWT specifically for the downstream service
func (pm *ProxyManager) createProxyJWT(auth *AuthResult, targetHost string) (string, error) {
	// Create a new JWT specifically for the downstream service
	proxyClaims := &AccessTokenClaims{
		Scope:    auth.Claims.Scope, // Use actual user scopes
		ClientID: "gateway-proxy",
		IDP:      auth.Claims.IDP,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   auth.UserID,
			Issuer:    pm.gatewayIssuer,              // Gateway as issuer
			Audience:  []string{targetHost, "proxy"}, // Audience = target service
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)), // Short-lived proxy token
			ID:        pm.generateJTI(),
		},
	}

	// Sign the token using the token service
	return pm.validator.sign(*proxyClaims)
}

// injectUserClaimsAsHeaders injects individual user claims as HTTP headers
func (pm *ProxyManager) injectUserClaimsAsHeaders(r *http.Request, auth *AuthResult, customMappings map[string]string) {
	// Default claim mappings
	defaultMappings := map[string]string{
		"subject":            "X-User-Subject",
		"issuer":             "X-Token-Issuer",
		"audience":           "X-Token-Audience",
		"token_id":           "X-Token-ID",
		"issued_at":          "X-Token-Issued",
		"expires_at":         "X-Token-Expires",
		"idp":                "X-User-IDP",
		"email":              "X-User-Email",
		"name":               "X-User-Name",
		"preferred_username": "X-User-Username",
		"groups":             "X-User-Groups",
		"roles":              "X-User-Roles",
	}

	// Merge with custom mappings
	for claim, header := range customMappings {
		defaultMappings[claim] = header
	}

	if auth.Claims != nil {
		// Inject claims from access token
		r.Header.Set(defaultMappings["subject"], auth.Claims.Subject)
		r.Header.Set(defaultMappings["issuer"], auth.Claims.Issuer)
		// Join audiences from the RegisteredClaims field
		audiences := make([]string, len(auth.Claims.Audience))
		for i, aud := range auth.Claims.Audience {
			audiences[i] = aud
		}
		r.Header.Set(defaultMappings["audience"], strings.Join(audiences, ","))
		r.Header.Set(defaultMappings["token_id"], auth.Claims.ID)
		r.Header.Set(defaultMappings["issued_at"], auth.Claims.IssuedAt.Format(time.RFC3339))
		r.Header.Set(defaultMappings["expires_at"], auth.Claims.ExpiresAt.Format(time.RFC3339))
		r.Header.Set(defaultMappings["idp"], auth.Claims.IDP)
	}

	// Try to get user profile information from session or claims
	if auth.Session != nil {
		// In a real implementation, we'd fetch user profile from storage
		// For now, we'll extract basic info from session
		if email := pm.extractEmailFromSession(auth.Session); email != "" {
			r.Header.Set(defaultMappings["email"], email)
		}
	}
}

// extractEmailFromSession extracts email from session (placeholder implementation)
func (pm *ProxyManager) extractEmailFromSession(session *Session) string {
	// This would typically fetch from user profile storage
	// For now, return a placeholder
	parts := strings.Split(session.UserID, ":")
	if len(parts) >= 2 {
		return fmt.Sprintf("user@%s.local", parts[1][:min(len(parts[1]), 8)])
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// shouldSkipAuth checks if the request path should skip authentication
func (pm *ProxyManager) shouldSkipAuth(route *proxyRoute, path string) bool {
	// Auto-exclude common health check and static content paths
	autoExcludedPaths := []string{
		"/health", "/healthz", "/ping", "/status",
		"/metrics", "/prometheus", "/ready", "/liveness",
		"/favicon.ico", "/robots.txt", "/sitemap.xml",
		"/static/", "/assets/", "/css/", "/js/", "/images/",
	}

	// Check auto-excluded paths first
	for _, excludedPath := range autoExcludedPaths {
		if strings.HasPrefix(path, excludedPath) {
			return true
		}
	}

	// Check configured skip paths
	for _, skipPath := range route.skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}

	return false
}

// handleAuthError handles authentication failures with smart redirects
func (pm *ProxyManager) handleAuthError(w http.ResponseWriter, r *http.Request, route *proxyRoute, authErr error) {
	pm.logger.Debug("authentication failed",
		"host", route.host,
		"path", r.URL.Path,
		"error", authErr)

	// Check if this is an API request (no redirect)
	if pm.isAPIRequest(r) {
		pm.writeAuthErrorJSON(w, authErr)
		return
	}

	// For browser requests, redirect to authentication
	redirectURL := route.authRedirectURL
	if redirectURL == "" {
		redirectURL = "/authorize" // Default gateway auth endpoint
	}

	// Store original request path for post-auth redirect
	// Encode the original host and path in the state parameter
	state := pm.generateStateParameter(r.Host, r.URL.String())

	// Generate PKCE parameters
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		pm.logger.Error("failed to generate PKCE verifier", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// TODO: Store verifier in session for token exchange
	// For now, we'll need to implement session storage for PKCE verifiers

	// Build the full redirect URI (scheme + host + path)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	fullRedirectURI := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.String())

	// Build auth URL with current request context and PKCE
	authURL := fmt.Sprintf("%s?client_id=gateway-proxy&redirect_uri=%s&response_type=code&scope=openid profile email&state=%s&code_challenge=%s&code_challenge_method=S256",
		redirectURL,
		url.QueryEscape(fullRedirectURI),
		state,
		challenge)

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOAuthCallback processes the OAuth callback with authorization code
func (pm *ProxyManager) handleOAuthCallback(w http.ResponseWriter, r *http.Request, route *proxyRoute) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	pm.logger.Info("oauth callback received", "code", code[:8]+"...", "state", state)

	// Parse the state to get the original host and path
	originalHost, originalPath, ok := pm.parseStateParameter(state)
	if !ok {
		pm.logger.Error("failed to parse state parameter", "state", state)
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	pm.logger.Info("parsed redirect info from state", "host", originalHost, "path", originalPath)

	// Fetch and consume the authorization code from storage
	authCode, ok := pm.store.ConsumeAuthCode(code)
	if !ok {
		pm.logger.Error("failed to consume authorization code", "code", code)
		http.Error(w, "Invalid or expired authorization code", http.StatusBadRequest)
		return
	}

	// Check if there's an existing session for this auth code
	session, ok := pm.store.GetSession(authCode.SessionID)
	if !ok {
		pm.logger.Error("session not found for authorization code", "session_id", authCode.SessionID)
		http.Error(w, "Session not found", http.StatusBadRequest)
		return
	}

	// Create a new session cookie for the proxy
	newSession := Session{
		ID:        pm.store.NewID(),
		UserID:    session.UserID,
		IDP:       session.IDP,
		AuthTime:  session.AuthTime,
		ExpiresAt: time.Now().Add(12 * time.Hour), // TODO: Use config
		AMR:       session.AMR,
		ACR:       session.ACR,
	}

	// Save the new session
	pm.store.SaveSession(newSession)

	// Set session cookie (using same name as SessionManager)
	http.SetCookie(w, &http.Cookie{
		Name:     "gw_session",
		Value:    newSession.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((12 * time.Hour).Seconds()),
	})

	pm.logger.Info("session created for proxy auth", "session_id", newSession.ID, "user_id", newSession.UserID)

	// Redirect back to the original host and path
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	redirectURL := fmt.Sprintf("%s://%s%s", scheme, originalHost, originalPath)
	pm.logger.Info("redirecting to original URL", "url", redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// isAPIRequest determines if this is an API request that should return JSON errors
func (pm *ProxyManager) isAPIRequest(r *http.Request) bool {
	accept := r.Header.Get("Accept")

	// Check for API patterns
	if strings.Contains(accept, "application/json") ||
		strings.HasPrefix(r.URL.Path, "/api/") ||
		strings.HasPrefix(r.URL.Path, "/v1/") ||
		strings.HasPrefix(r.URL.Path, "/v2/") {
		return true
	}

	return false
}

// writeAuthErrorJSON writes authentication error as JSON
func (pm *ProxyManager) writeAuthErrorJSON(w http.ResponseWriter, authErr error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="gateway"`)

	var statusCode int
	var errorCode string

	switch {
	case strings.Contains(authErr.Error(), "scopes"):
		statusCode = http.StatusForbidden
		errorCode = "insufficient_scope"
	default:
		statusCode = http.StatusUnauthorized
		errorCode = "missing_authentication"
	}

	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":             errorCode,
		"error_description": authErr.Error(),
		"timestamp":         time.Now().Format(time.RFC3339),
	})
}

// generateStateParameter generates a unique state parameter
func (pm *ProxyManager) generateStateParameter(host, path string) string {
	// Encode the original host and path in base64 so we can redirect back after auth
	redirectInfo := fmt.Sprintf("%s|%s", host, path)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(redirectInfo))
	return fmt.Sprintf("proxy_auth_%d_%s", time.Now().UnixNano(), encoded)
}

func (pm *ProxyManager) parseStateParameter(state string) (host, path string, ok bool) {
	// State format: proxy_auth_{timestamp}_{base64(host|path)}
	parts := strings.SplitN(state, "_", 3)
	if len(parts) != 3 || parts[0] != "proxy" || parts[1] != "auth" {
		return "", "", false
	}

	// Extract the encoded part after the second underscore
	encoded := parts[2]
	idx := strings.Index(encoded, "_")
	if idx == -1 {
		return "", "", false
	}
	encoded = encoded[idx+1:]

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}

	redirectParts := strings.SplitN(string(decoded), "|", 2)
	if len(redirectParts) != 2 {
		return "", "", false
	}

	return redirectParts[0], redirectParts[1], true
}

// proxyRequest forwards the request to the upstream service
func (pm *ProxyManager) proxyRequest(w http.ResponseWriter, r *http.Request, route *proxyRoute, auth *AuthResult) {
	pm.logger.Debug("proxying request",
		"host", route.host,
		"path", r.URL.Path,
		"method", r.Method,
		"authenticated", auth != nil,
	)

	// Add auth context if available
	if auth != nil {
		ctx := context.WithValue(r.Context(), "auth_result", auth)
		r = r.WithContext(ctx)
	}

	route.proxy.ServeHTTP(w, r)
}

func (pm *ProxyManager) schemeFromRequest(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}
