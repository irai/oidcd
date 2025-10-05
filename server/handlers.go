package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

const localProviderName = "local"

// App bundles runtime dependencies for the HTTP service.
type App struct {
	Config            Config
	Logger            *slog.Logger
	Store             *InMemoryStore
	Sessions          *SessionManager
	Tokens            *TokenService
	JWKS              *JWKSManager
	Clients           *ClientRegistry
	Providers         map[string]IdentityProvider
	DefaultProvider   string
	Debug             *DebugAuthManager
	DebugClientID     string
	DebugRedirect     string
	DebugClient       *Client
	DebugClientSecret string
	Proxy             *ProxyManager
}

// NewApp wires together the application state from configuration.
func NewApp(ctx context.Context, cfg Config, logger *slog.Logger) (*App, error) {
	store := NewInMemoryStore()

	jwks, err := NewJWKSManager(cfg.Server.SecretsPath, logger)
	if err != nil {
		return nil, err
	}

	tokens := NewTokenService(cfg, store, jwks, logger)
	sessions := NewSessionManager(cfg, store, logger)
	clients, err := NewClientRegistry(cfg.OAuth2Clients)
	if err != nil {
		return nil, err
	}

	providers, err := BuildProviders(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}

	defaultProvider := cfg.Server.Providers.Default
	if cfg.Server.DevMode && defaultProvider == "" {
		defaultProvider = localProviderName
	}

	app := &App{
		Config:          cfg,
		Logger:          logger,
		Store:           store,
		Sessions:        sessions,
		Tokens:          tokens,
		JWKS:            jwks,
		Clients:         clients,
		Providers:       providers,
		DefaultProvider: defaultProvider,
	}

	if cfg.Server.DevMode {
		debugRedirect := strings.TrimSuffix(cfg.Server.PublicURL, "/") + "/dev/auth/result"
		var debugClient *Client
		if len(cfg.OAuth2Clients) > 0 {
			firstID := cfg.OAuth2Clients[0].ClientID
			if c, ok := clients.Get(firstID); ok {
				debugClient = c
			}
		}
		if debugClient == nil {
			debugClient = &Client{
				ClientID:     debugClientID,
				ClientSecret: "",
				RedirectURIs: []string{debugRedirect},
				Scopes:       []string{"openid", "profile", "email"},
				Audiences:    []string{cfg.Server.ServerID},
				Public:       true,
			}
			clients.Add(debugClient)
		}
		if !slices.Contains(debugClient.RedirectURIs, debugRedirect) {
			debugClient.RedirectURIs = append(debugClient.RedirectURIs, debugRedirect)
		}
		app.Debug = NewDebugAuthManager()
		app.DebugClient = debugClient
		app.DebugClientID = debugClient.ClientID
		app.DebugClientSecret = debugClient.ClientSecret
		app.DebugRedirect = debugRedirect
	}

	// Initialize proxy if routes are configured
	if len(cfg.Proxy.Routes) > 0 {
		// Register internal proxy client if not already configured
		proxyClientID := "gateway-proxy"
		if _, exists := clients.Get(proxyClientID); !exists {
			// Auto-register internal proxy client with wildcard redirect URIs
			internalProxyClient := &Client{
				ClientID:     proxyClientID,
				ClientSecret: "",
				RedirectURIs: []string{"*"}, // Accept any redirect URI for proxy callbacks
				Scopes:       []string{"openid", "profile", "email"},
				Audiences:    []string{"proxy"},
				Public:       true,
			}
			clients.Add(internalProxyClient)
			logger.Info("auto-registered internal proxy client", "client_id", proxyClientID)
		}

		proxy, err := NewProxyManager(cfg.Proxy, tokens, sessions, store, cfg.Server, logger)
		if err != nil {
			return nil, fmt.Errorf("init proxy: %w", err)
		}
		app.Proxy = proxy
	}

	return app, nil
}

func (a *App) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	metadata := BuildDiscoveryDocument(a.Config)
	writeJSON(w, metadata)
}

func (a *App) handleJWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.JWKS.PublicJWKS())
}

func (a *App) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, "", "", "invalid_request", "invalid form")
		return
	}

	req, err := a.parseAuthorizeRequest(r)
	if err != nil {
		a.Logger.Warn("authorize invalid request", "error", err)
		// Only redirect if we have a valid client AND registered redirect_uri
		// Per OAuth2 spec, if redirect_uri is invalid/unregistered, return error directly
		canRedirect := req.Client != nil && req.RedirectURI != "" && req.Client.ValidRedirect(req.RedirectURI)
		if canRedirect {
			oauthError(w, req.RedirectURI, req.State, "invalid_request", err.Error())
		} else {
			http.Error(w, fmt.Sprintf("invalid_request: %s", err.Error()), http.StatusBadRequest)
		}
		return
	}

	session, err := a.Sessions.Fetch(r)
	if err != nil {
		a.Logger.Warn("session fetch error", "error", err)
	}

	if session != nil && session.ExpiresAt.After(time.Now()) {
		if err := a.completeAuthorize(w, r, req, session); err != nil {
			a.Logger.Error("authorize issue code", "error", err)
			oauthError(w, req.RedirectURI, req.State, "server_error", "failed to issue code")
		}
		return
	}

	providerName := req.Provider
	provider, ok := a.Providers[providerName]
	if !ok {
		if a.Config.Server.DevMode && providerName == localProviderName {
			req.Provider = localProviderName
			if err := a.handleDevAuthorize(w, r, req); err != nil {
				a.Logger.Error("dev authorize failed", "error", err)
				oauthError(w, req.RedirectURI, req.State, "server_error", "dev login failed")
			}
			return
		}
		a.Logger.Error("unknown provider", "provider", providerName)
		oauthError(w, req.RedirectURI, req.State, "server_error", "provider not available")
		return
	}

	loginReq := AuthRequest{
		ID:                  a.Store.NewID(),
		ClientID:            req.Client.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Provider:            providerName,
		Audience:            req.Audience,
		CreatedAt:           time.Now(),
		PKCERequired:        req.Client.Public,
	}
	a.Store.SaveAuthRequest(loginReq)

	redirectURL := provider.AuthCodeURL(loginReq.ID, req.Nonce, "", "")
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (a *App) handleDevAuthorize(w http.ResponseWriter, r *http.Request, req AuthorizeRequest) error {
	user := ProviderUser{
		Subject: "dev-user",
		Email:   "dev@example.com",
		Name:    "Dev User",
	}
	session, err := a.Sessions.Create(w, r, localProviderName, user)
	if err != nil {
		return err
	}
	a.Store.RememberUserProfile(localProviderName, user)
	return a.completeAuthorize(w, r, req, session)
}

func (a *App) handleCallback(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "idp")
	provider, ok := a.Providers[providerName]
	if !ok {
		http.Error(w, "provider not configured", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid callback", http.StatusBadRequest)
		return
	}

	state := r.FormValue("state")
	code := r.FormValue("code")
	if state == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}

	authReq, ok := a.Store.ConsumeAuthRequest(state)
	if !ok {
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}

	if authReq.Provider != providerName {
		http.Error(w, "state provider mismatch", http.StatusBadRequest)
		return
	}

	client, ok := a.Clients.Get(authReq.ClientID)
	if !ok {
		http.Error(w, "client not found", http.StatusBadRequest)
		return
	}

	isDebugFlow := a.Debug != nil && authReq.ClientID == a.DebugClientID
	ctx := r.Context()
	user, err := provider.Exchange(ctx, code, authReq.Nonce)
	if err != nil {
		if a.Debug != nil {
			a.Debug.RecordProviderResponse(authReq.State, nil, fmt.Sprintf("exchange failed: %v", err))
			a.Debug.RecordTokenResult(authReq.State, nil, fmt.Sprintf("exchange failed: %v", err))
		}
		a.Logger.Error("exchange failed", "error", err)
		if isDebugFlow {
			http.Redirect(w, r, a.debugResultURL(authReq.State, "upstream_exchange"), http.StatusSeeOther)
			return
		}
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	if a.Debug != nil {
		a.Debug.RecordProviderResponse(authReq.State, &user, "")
	}

	session, err := a.Sessions.Create(w, r, providerName, user)
	if err != nil {
		a.Logger.Error("session create", "error", err)
		if a.Debug != nil {
			a.Debug.RecordTokenResult(authReq.State, nil, fmt.Sprintf("session create failed: %v", err))
		}
		if isDebugFlow {
			http.Redirect(w, r, a.debugResultURL(authReq.State, "session_create"), http.StatusSeeOther)
			return
		}
		http.Error(w, "session failure", http.StatusInternalServerError)
		return
	}

	a.Store.RememberUserProfile(providerName, user)

	req := AuthorizeRequest{
		Client:              client,
		RedirectURI:         authReq.RedirectURI,
		Scope:               authReq.Scope,
		State:               authReq.State,
		Nonce:               authReq.Nonce,
		CodeChallenge:       authReq.CodeChallenge,
		CodeChallengeMethod: authReq.CodeChallengeMethod,
		Audience:            authReq.Audience,
		Provider:            providerName,
	}

	if err := a.completeAuthorize(w, r, req, session); err != nil {
		a.Logger.Error("callback issue code", "error", err)
		if a.Debug != nil {
			a.Debug.RecordTokenResult(authReq.State, nil, fmt.Sprintf("complete authorize failed: %v", err))
		}
		if isDebugFlow {
			http.Redirect(w, r, a.debugResultURL(authReq.State, "issue_code"), http.StatusSeeOther)
			return
		}
		oauthError(w, req.RedirectURI, req.State, "server_error", "failed to issue code")
		return
	}
}

func (a *App) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	client, err := a.authenticateClient(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	grantType := r.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		a.handleTokenAuthorizationCode(w, r, client)
	case "refresh_token":
		a.handleTokenRefresh(w, r, client)
	case "client_credentials":
		a.handleTokenClientCredentials(w, r, client)
	default:
		http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
	}
}

func (a *App) handleTokenAuthorizationCode(w http.ResponseWriter, r *http.Request, client *Client) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	authCode, ok := a.Store.ConsumeAuthCode(code)
	if !ok {
		oauthError(w, "", "", "invalid_grant", "code invalid or expired")
		return
	}

	if authCode.ClientID != client.ClientID {
		oauthError(w, "", "", "invalid_grant", "client mismatch")
		return
	}
	if authCode.RedirectURI != redirectURI {
		oauthError(w, "", "", "invalid_grant", "redirect_uri mismatch")
		return
	}

	if authCode.CodeChallenge != "" {
		if err := verifyPKCE(authCode, codeVerifier); err != nil {
			oauthError(w, "", "", "invalid_grant", err.Error())
			return
		}
	}

	tokens, err := a.Tokens.MintForAuthorizationCode(r.Context(), authCode, client)
	if err != nil {
		a.Logger.Error("mint auth code", "error", err)
		oauthError(w, "", "", "server_error", "failed to mint token")
		return
	}

	writeJSON(w, tokens)
}

func (a *App) handleTokenRefresh(w http.ResponseWriter, r *http.Request, client *Client) {
	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		oauthError(w, "", "", "invalid_request", "missing refresh_token")
		return
	}

	tokens, err := a.Tokens.MintForRefreshToken(r.Context(), refreshToken, client)
	if err != nil {
		a.Logger.Warn("refresh failed", "error", err)
		oauthError(w, "", "", "invalid_grant", err.Error())
		return
	}

	writeJSON(w, tokens)
}

func (a *App) handleTokenClientCredentials(w http.ResponseWriter, r *http.Request, client *Client) {
	scope := r.FormValue("scope")
	audience := r.FormValue("audience")

	tokens, err := a.Tokens.MintForClientCredentials(r.Context(), client, scope, audience)
	if err != nil {
		a.Logger.Warn("client credentials", "error", err)
		oauthError(w, "", "", "invalid_client", err.Error())
		return
	}

	writeJSON(w, tokens)
}

func (a *App) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r.Header.Get("Authorization"))
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	claims, err := a.Tokens.ValidateAccessToken(r.Context(), token)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	scope := claims.Scope
	profile := a.Store.LookupUserProfile(claims.Subject)

	resp := map[string]any{
		"sub": claims.Subject,
	}
	if profile != nil {
		if strings.Contains(scope, "email") && profile.Email != "" {
			resp["email"] = profile.Email
		}
		if strings.Contains(scope, "profile") && profile.Name != "" {
			resp["name"] = profile.Name
		}
	}

	writeJSON(w, resp)
}

func (a *App) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	client, err := a.authenticateClient(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}

	activeResp := a.Tokens.Introspect(token, client)
	writeJSON(w, activeResp)
}

func (a *App) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	client, err := a.authenticateClient(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}

	a.Tokens.Revoke(r.Context(), client, token)
	w.WriteHeader(http.StatusOK)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	a.Sessions.Clear(w)
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) parseAuthorizeRequest(r *http.Request) (AuthorizeRequest, error) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	if clientID == "" {
		return AuthorizeRequest{}, errors.New("client_id required")
	}

	client, ok := a.Clients.Get(clientID)
	if !ok {
		return AuthorizeRequest{RedirectURI: q.Get("redirect_uri"), State: q.Get("state")}, fmt.Errorf("unknown client")
	}

	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" || !client.ValidRedirect(redirectURI) {
		return AuthorizeRequest{Client: client, RedirectURI: redirectURI, State: q.Get("state")}, fmt.Errorf("invalid redirect_uri")
	}

	responseType := q.Get("response_type")
	if responseType != "code" {
		return AuthorizeRequest{Client: client, RedirectURI: redirectURI, State: q.Get("state")}, fmt.Errorf("unsupported response_type")
	}

	scope := q.Get("scope")
	if scope == "" {
		scope = "openid"
	}
	if !strings.Contains(scope, "openid") {
		return AuthorizeRequest{Client: client, RedirectURI: redirectURI, State: q.Get("state")}, fmt.Errorf("scope must include openid")
	}

	codeChallenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	if client.Public {
		if method != "S256" || codeChallenge == "" {
			return AuthorizeRequest{Client: client, RedirectURI: redirectURI, State: q.Get("state")}, fmt.Errorf("pkce required")
		}
	}

	provider := q.Get("idp")
	if provider == "" {
		if a.DefaultProvider != "" {
			provider = a.DefaultProvider
		} else if a.Config.Server.DevMode {
			provider = localProviderName
		}
	}

	audience := q.Get("audience")
	if audience == "" {
		audience = a.Config.Server.ServerID
	}

	return AuthorizeRequest{
		Client:              client,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: method,
		Audience:            audience,
		Provider:            provider,
	}, nil
}

func (a *App) completeAuthorize(w http.ResponseWriter, r *http.Request, req AuthorizeRequest, session *Session) error {
	code := a.Store.NewID()
	authCode := AuthorizationCode{
		Code:                code,
		ClientID:            req.Client.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		SessionID:           session.ID,
		UserID:              session.UserID,
		IDP:                 session.IDP,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(5 * time.Minute),
		Audience:            req.Audience,
	}
	a.Store.SaveAuthCode(authCode)

	redirect, err := url.Parse(req.RedirectURI)
	if err != nil {
		return err
	}
	values := redirect.Query()
	values.Set("code", code)
	if req.State != "" {
		values.Set("state", req.State)
	}
	redirect.RawQuery = values.Encode()

	http.Redirect(w, r, redirect.String(), http.StatusFound)
	return nil
}

func (a *App) authenticateClient(r *http.Request) (*Client, error) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}
	return a.Clients.Authenticate(clientID, clientSecret)
}

// AuthorizeRequest encapsulates parsed parameters for /authorize.
type AuthorizeRequest struct {
	Client              *Client
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Audience            string
	Provider            string
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, redirectURI, state, code, desc string) {
	// Never redirect to unsafe URIs - always return error as JSON instead
	if redirectURI == "" || !isSafeRedirectURI(redirectURI) {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
		return
	}

	uri, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, desc, http.StatusBadRequest)
		return
	}
	q := uri.Query()
	q.Set("error", code)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	uri.RawQuery = q.Encode()
	// Use manual redirect to avoid nil request panic
	w.Header().Set("Location", uri.String())
	w.WriteHeader(http.StatusFound)
}

func extractBearerToken(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
