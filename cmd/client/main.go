package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/oauth2"
)

type Config struct {
	ListenAddr    string
	OIDCIssuer    string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	Scopes        []string
}

type App struct {
	cfg      Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth2   oauth2.Config
	sessions map[string]*SessionData
	mu       sync.RWMutex
	logger   *slog.Logger
}

type SessionData struct {
	State        string
	Nonce        string
	CodeVerifier string
	Token        *oauth2.Token
	IDToken      string
	Claims       map[string]interface{}
}

func main() {
	listenAddr := flag.String("listen", getEnv("LISTEN_ADDR", "127.0.0.1:3000"), "Listen address")
	issuer := flag.String("issuer", getEnv("OIDC_ISSUER", "http://127.0.0.1:8080"), "OIDC issuer URL")
	clientID := flag.String("client-id", getEnv("CLIENT_ID", "webapp"), "OAuth client ID")
	clientSecret := flag.String("client-secret", getEnv("CLIENT_SECRET", ""), "OAuth client secret")
	redirectURL := flag.String("redirect-url", getEnv("REDIRECT_URL", "http://127.0.0.1:3000/callback"), "OAuth redirect URL")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := Config{
		ListenAddr:   *listenAddr,
		OIDCIssuer:   *issuer,
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		RedirectURL:  *redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
	cancel()
	if err != nil {
		log.Fatalf("failed to create OIDC provider: %v", err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	oauth2Config := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}

	app := &App{
		cfg:      cfg,
		provider: provider,
		verifier: verifier,
		oauth2:   oauth2Config,
		sessions: make(map[string]*SessionData),
		logger:   logger,
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", app.handleHome)
	r.Get("/login", app.handleLogin)
	r.Get("/callback", app.handleCallback)
	r.Get("/profile", app.handleProfile)
	r.Get("/logout", app.handleLogout)

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("client app listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func (a *App) handleHome(w http.ResponseWriter, r *http.Request) {
	sessionID, err := r.Cookie("session_id")
	var session *SessionData
	if err == nil {
		a.mu.RLock()
		session = a.sessions[sessionID.Value]
		a.mu.RUnlock()
	}

	tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>OIDC Test Client</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        h1 { color: #333; }
        .status { padding: 10px; margin: 20px 0; border-radius: 5px; }
        .authenticated { background-color: #d4edda; color: #155724; }
        .unauthenticated { background-color: #f8d7da; color: #721c24; }
        .button { display: inline-block; padding: 10px 20px; margin: 10px 5px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px; }
        .button:hover { background-color: #0056b3; }
        .logout { background-color: #dc3545; }
        .logout:hover { background-color: #c82333; }
    </style>
</head>
<body>
    <h1>OIDC Test Client</h1>
    {{if .Authenticated}}
    <div class="status authenticated">
        <p><strong>✓ Authenticated</strong></p>
        <p>Username: <strong>{{.Username}}</strong></p>
        <p>Email: {{.Email}}</p>
    </div>
    <a href="/profile" class="button">View Full Profile</a>
    <a href="/logout" class="button logout">Logout</a>
    {{else}}
    <div class="status unauthenticated">
        <p><strong>✗ Not Authenticated</strong></p>
        <p>Please login to test the OIDC flow with Microsoft 365</p>
    </div>
    <a href="/login" class="button">Login with OIDC</a>
    {{end}}
</body>
</html>`

	t := template.Must(template.New("home").Parse(tmpl))

	data := map[string]interface{}{
		"Authenticated": session != nil && session.Token != nil,
	}

	if session != nil && session.Claims != nil {
		if username, ok := session.Claims["preferred_username"].(string); ok {
			data["Username"] = username
		} else if name, ok := session.Claims["name"].(string); ok {
			data["Username"] = name
		} else if email, ok := session.Claims["email"].(string); ok {
			data["Username"] = email
		}

		if email, ok := session.Claims["email"].(string); ok {
			data["Email"] = email
		}
	}

	w.Header().Set("Content-Type", "text/html")
	t.Execute(w, data)
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := randomString(32)
	nonce := randomString(32)
	codeVerifier := oauth2.GenerateVerifier()

	sessionID := randomString(32)
	a.mu.Lock()
	a.sessions[sessionID] = &SessionData{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
	}
	a.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(a.cfg.RedirectURL, "https"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	})

	authURL := a.oauth2.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(codeVerifier),
		oidc.Nonce(nonce),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (a *App) handleCallback(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		a.logger.Error("no session cookie", "error", err)
		http.Error(w, "No session cookie", http.StatusBadRequest)
		return
	}

	a.mu.RLock()
	session := a.sessions[sessionCookie.Value]
	a.mu.RUnlock()

	if session == nil {
		a.logger.Error("invalid session", "session_id", sessionCookie.Value)
		http.Error(w, "Invalid session", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	if state != session.State {
		a.logger.Error("state mismatch", "expected", session.State, "got", state)
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		a.logger.Error("no code in callback")
		http.Error(w, "No code in callback", http.StatusBadRequest)
		return
	}

	a.logger.Info("exchanging code for token", "code_prefix", code[:min(8, len(code))])

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	token, err := a.oauth2.Exchange(ctx, code, oauth2.VerifierOption(session.CodeVerifier))
	if err != nil {
		a.logger.Error("token exchange failed", "error", err, "token_endpoint", a.oauth2.Endpoint.TokenURL)
		http.Error(w, fmt.Sprintf("Token exchange failed: %v", err), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		a.logger.Error("no id_token in response", "token_extras", fmt.Sprintf("%+v", token))
		http.Error(w, "No id_token in response", http.StatusInternalServerError)
		return
	}

	a.logger.Info("verifying id_token", "id_token_prefix", rawIDToken[:min(20, len(rawIDToken))])

	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		a.logger.Error("id_token verification failed", "error", err)
		http.Error(w, fmt.Sprintf("ID token verification failed: %v", err), http.StatusInternalServerError)
		return
	}

	if idToken.Nonce != session.Nonce {
		http.Error(w, "Nonce mismatch", http.StatusBadRequest)
		return
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		a.logger.Error("failed to parse claims", "error", err)
		http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
		return
	}

	a.mu.Lock()
	session.Token = token
	session.IDToken = rawIDToken
	session.Claims = claims
	a.mu.Unlock()

	a.logger.Info("user authenticated", "sub", idToken.Subject)

	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *App) handleProfile(w http.ResponseWriter, r *http.Request) {
	sessionID, err := r.Cookie("session_id")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	a.mu.RLock()
	session := a.sessions[sessionID.Value]
	a.mu.RUnlock()

	if session == nil || session.Token == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        h1 { color: #333; }
        pre { background-color: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .button { display: inline-block; padding: 10px 20px; margin: 10px 5px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px; }
        .button:hover { background-color: #0056b3; }
    </style>
</head>
<body>
    <h1>User Profile</h1>
    <h2>ID Token Claims (from JWT)</h2>
    <pre>{{.Claims}}</pre>
    <h2>Access Token</h2>
    <pre>{{.AccessToken}}</pre>
    <a href="/" class="button">Back to Home</a>
</body>
</html>`

	t := template.Must(template.New("profile").Parse(tmpl))

	claimsJSON, _ := json.MarshalIndent(session.Claims, "", "  ")

	data := map[string]interface{}{
		"Claims":      string(claimsJSON),
		"AccessToken": session.Token.AccessToken,
	}

	w.Header().Set("Content-Type", "text/html")
	t.Execute(w, data)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID, err := r.Cookie("session_id")
	if err == nil {
		a.mu.Lock()
		delete(a.sessions, sessionID.Value)
		a.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
