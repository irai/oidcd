package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"oidcd/client"
)

type stubIdentityProvider struct {
	mu           sync.Mutex
	callbackBase string
	issued       map[string]issuedAuth
}

type issuedAuth struct {
	user  ProviderUser
	nonce string
}

func newStubIdentityProvider() *stubIdentityProvider {
	return &stubIdentityProvider{issued: make(map[string]issuedAuth)}
}

func (s *stubIdentityProvider) setCallbackBase(base string) {
	s.mu.Lock()
	s.callbackBase = strings.TrimSuffix(base, "/")
	s.mu.Unlock()
}

func (s *stubIdentityProvider) AuthCodeURL(state, nonce, codeChallenge, method string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.callbackBase == "" {
		panic("callback base not configured")
	}
	code := fmt.Sprintf("code-%d", time.Now().UnixNano())
	s.issued[code] = issuedAuth{
		user: ProviderUser{
			Subject: "user-123",
			Email:   "user@example.com",
			Name:    "Test User",
			Claims:  map[string]any{"nonce": nonce},
		},
		nonce: nonce,
	}
	return fmt.Sprintf("%s/callback/stub?code=%s&state=%s", s.callbackBase, code, state)
}

func (s *stubIdentityProvider) Exchange(ctx context.Context, code, expectedNonce string) (ProviderUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	issued, ok := s.issued[code]
	if !ok {
		return ProviderUser{}, fmt.Errorf("unknown code %s", code)
	}
	delete(s.issued, code)
	if expectedNonce != "" && issued.nonce != expectedNonce {
		return ProviderUser{}, fmt.Errorf("nonce mismatch")
	}
	return issued.user, nil
}

type integrationSetup struct {
	t            *testing.T
	logger       *slog.Logger
	cfg          Config
	stubIDP      *stubIdentityProvider
	gateway      *httptest.Server
	micro        *httptest.Server
	clientSrv    *httptest.Server
	httpClient   *http.Client
	tokens       *TokenService
	store        *InMemoryStore
	jwks         *JWKSManager
	codeCh       chan url.Values
	clientID     string
	clientSecret string
	redirectURI  string
	state        string
}

func newIntegrationSetup(t *testing.T, modify func(*Config)) *integrationSetup {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	setup := &integrationSetup{
		t:      t,
		logger: logger,
		codeCh: make(chan url.Values, 1),
		state:  "state123",
	}

	setup.clientSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case setup.codeCh <- r.URL.Query():
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	setup.redirectURI = setup.clientSrv.URL + "/callback"

	cfg := DefaultConfig()
	cfg.Server.DevMode = true
	cfg.Server.PublicURL = "http://gateway.test"
	cfg.Clients = []ClientConfig{{
		ClientID:     "test-client",
		ClientSecret: "supersecret",
		RedirectURIs: []string{setup.redirectURI},
		Scopes:       []string{"openid", "profile", "email"},
		Audiences:    []string{"api://default"},
	}}
	cfg.Tokens.AudienceDefault = "api://default"
	cfg.Tokens.AccessTTL = time.Minute
	cfg.Tokens.RefreshTTL = 24 * time.Hour

	if modify != nil {
		modify(&cfg)
	}

	setup.cfg = cfg
	if len(cfg.Clients) == 0 {
		t.Fatalf("expected at least one client")
	}
	setup.clientID = cfg.Clients[0].ClientID
	setup.clientSecret = cfg.Clients[0].ClientSecret

	store := NewInMemoryStore()
	jwks, err := NewJWKSManager(cfg.Keys, logger)
	if err != nil {
		t.Fatalf("jwks manager: %v", err)
	}
	tokens := NewTokenService(cfg, store, jwks, logger)
	sessions := NewSessionManager(cfg, store, logger)
	clients, err := NewClientRegistry(cfg.Clients)
	if err != nil {
		t.Fatalf("client registry: %v", err)
	}

	stubIDP := newStubIdentityProvider()
	application := &App{
		Config:          cfg,
		Logger:          logger,
		Store:           store,
		Sessions:        sessions,
		Tokens:          tokens,
		JWKS:            jwks,
		Clients:         clients,
		Providers:       map[string]IdentityProvider{"stub": stubIDP},
		DefaultProvider: "stub",
	}

	gateway := httptest.NewServer(application.Routes())
	stubIDP.setCallbackBase(gateway.URL)

	validator := client.NewValidator(client.ValidatorConfig{
		Issuer:            cfg.Server.PublicURL,
		JWKSURL:           gateway.URL + "/jwks.json",
		ExpectedAudiences: []string{"api://default"},
		CacheTTL:          time.Minute,
	})

	protected := client.RequireAuth(validator, "profile")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := client.ClaimsFromContext(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":       claims.Subject,
			"client_id": claims.ClientID,
		})
	}))
	micro := httptest.NewServer(protected)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	httpClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}

	setup.stubIDP = stubIDP
	setup.gateway = gateway
	setup.micro = micro
	setup.httpClient = httpClient
	setup.tokens = tokens
	setup.store = store
	setup.jwks = jwks

	return setup
}

func (s *integrationSetup) Close() {
	s.micro.Close()
	s.gateway.Close()
	s.clientSrv.Close()
}

func (s *integrationSetup) Authorize(scope string) string {
	s.t.Helper()
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", s.clientID)
	params.Set("redirect_uri", s.redirectURI)
	params.Set("scope", scope)
	params.Set("state", s.state)
	params.Set("nonce", "n-1")

	resp, err := s.httpClient.Get(s.gateway.URL + "/authorize?" + params.Encode())
	if err != nil {
		s.t.Fatalf("authorize request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		s.t.Fatalf("expected redirect from authorize, got %d", resp.StatusCode)
	}

	callbackURL := resp.Header.Get("Location")
	if callbackURL == "" {
		s.t.Fatalf("missing callback redirect")
	}

	resp, err = s.httpClient.Get(callbackURL)
	if err != nil {
		s.t.Fatalf("callback request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		s.t.Fatalf("expected redirect to client, got %d", resp.StatusCode)
	}

	clientCallback := resp.Header.Get("Location")
	if clientCallback == "" {
		s.t.Fatalf("missing client redirect")
	}

	resp, err = s.httpClient.Get(clientCallback)
	if err != nil {
		s.t.Fatalf("client callback: %v", err)
	}
	resp.Body.Close()

	var query url.Values
	select {
	case query = <-s.codeCh:
	case <-time.After(2 * time.Second):
		s.t.Fatalf("timed out waiting for authorization code")
	}
	code := query.Get("code")
	if code == "" {
		s.t.Fatalf("authorization code missing")
	}
	return code
}

func (s *integrationSetup) Exchange(code string) TokenResponse {
	s.t.Helper()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", s.redirectURI)

	req, err := http.NewRequest(http.MethodPost, s.gateway.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		s.t.Fatalf("new token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(s.clientID, s.clientSecret)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.t.Fatalf("token exchange: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		s.t.Fatalf("token endpoint returned %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		s.t.Fatalf("decode token response: %v", err)
	}
	return tokenResp
}

func (s *integrationSetup) Refresh(refreshToken string) TokenResponse {
	s.t.Helper()
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	req, err := http.NewRequest(http.MethodPost, s.gateway.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		s.t.Fatalf("refresh request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(s.clientID, s.clientSecret)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.t.Fatalf("refresh token call: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		s.t.Fatalf("refresh token status %d", resp.StatusCode)
	}

	var refreshResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&refreshResp); err != nil {
		s.t.Fatalf("decode refresh response: %v", err)
	}
	return refreshResp
}

func (s *integrationSetup) CallMicro(token string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, s.micro.URL+"/protected", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return s.httpClient.Do(req)
}

func (s *integrationSetup) UserInfo(token string) (map[string]any, int, error) {
	req, err := http.NewRequest(http.MethodGet, s.gateway.URL+"/userinfo", nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func (s *integrationSetup) Introspect(token string) (map[string]any, int, error) {
	form := url.Values{}
	form.Set("token", token)

	req, err := http.NewRequest(http.MethodPost, s.gateway.URL+"/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(s.clientID, s.clientSecret)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func TestIntegrationAuthorizationCodeFlow(t *testing.T) {
	setup := newIntegrationSetup(t, nil)
	defer setup.Close()

	code := setup.Authorize("openid profile email")
	tokenResp := setup.Exchange(code)
	if tokenResp.AccessToken == "" || tokenResp.RefreshToken == "" {
		t.Fatalf("expected access and refresh tokens")
	}
	if tokenResp.Scope != "openid profile email" {
		t.Fatalf("unexpected scope %q", tokenResp.Scope)
	}

	claims, err := setup.tokens.ValidateAccessToken(context.Background(), tokenResp.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken error: %v", err)
	}
	if claims.Subject != "stub:user-123" {
		t.Fatalf("unexpected subject: %q", claims.Subject)
	}
	if claims.ClientID != setup.clientID {
		t.Fatalf("unexpected client id: %q", claims.ClientID)
	}
	if claims.IDP != "stub" {
		t.Fatalf("unexpected idp: %q", claims.IDP)
	}

	resp, err := setup.CallMicro(tokenResp.AccessToken)
	if err != nil {
		t.Fatalf("call microservice: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("microservice returned %d", resp.StatusCode)
	}
	var microBody map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&microBody); err != nil {
		t.Fatalf("decode micro response: %v", err)
	}
	resp.Body.Close()
	if microBody["sub"] != "stub:user-123" {
		t.Fatalf("unexpected subject from microservice: %v", microBody["sub"])
	}
	if microBody["client_id"] != setup.clientID {
		t.Fatalf("unexpected client id %v", microBody["client_id"])
	}

	userinfo, status, err := setup.UserInfo(tokenResp.AccessToken)
	if err != nil {
		t.Fatalf("userinfo call: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("userinfo status %d", status)
	}
	if userinfo["email"] != "user@example.com" {
		t.Fatalf("unexpected email %v", userinfo["email"])
	}
	if userinfo["name"] != "Test User" {
		t.Fatalf("unexpected name %v", userinfo["name"])
	}

	refreshResp := setup.Refresh(tokenResp.RefreshToken)
	if refreshResp.AccessToken == tokenResp.AccessToken {
		t.Fatalf("expected new access token on refresh")
	}
	if refreshResp.RefreshToken == "" {
		t.Fatalf("expected rotated refresh token")
	}
	if refreshResp.RefreshToken == tokenResp.RefreshToken {
		t.Fatalf("expected refresh token rotation")
	}

	introspectBody, status, err := setup.Introspect(refreshResp.AccessToken)
	if err != nil {
		t.Fatalf("introspect call: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("introspect status %d", status)
	}
	if active, ok := introspectBody["active"].(bool); !ok || !active {
		t.Fatalf("expected active token, got %v", introspectBody["active"])
	}
	if introspectBody["client_id"] != setup.clientID {
		t.Fatalf("unexpected client id from introspection %v", introspectBody["client_id"])
	}
}

func TestIntegrationInvalidToken(t *testing.T) {
	setup := newIntegrationSetup(t, nil)
	defer setup.Close()

	code := setup.Authorize("openid profile email")
	tokenResp := setup.Exchange(code)

	// Test with completely invalid token (not even JWT format)
	resp, err := setup.CallMicro("invalid-token")
	if err != nil {
		t.Fatalf("call microservice: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid token, got %d", resp.StatusCode)
	}

	// Test with tampered token (breaks signature)
	if len(tokenResp.AccessToken) < 10 {
		t.Fatalf("access token too short to tamper")
	}
	// Replace last character to break the signature
	tampered := tokenResp.AccessToken[:len(tokenResp.AccessToken)-1] + "x"

	resp, err = setup.CallMicro(tampered)
	if err != nil {
		t.Fatalf("call microservice with tampered token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for tampered token, got %d", resp.StatusCode)
	}
}

func TestIntegrationExpiredToken(t *testing.T) {
	setup := newIntegrationSetup(t, func(cfg *Config) {
		cfg.Tokens.AccessTTL = -1 * time.Minute
	})
	defer setup.Close()

	code := setup.Authorize("openid profile email")
	tokenResp := setup.Exchange(code)

	resp, err := setup.CallMicro(tokenResp.AccessToken)
	if err != nil {
		t.Fatalf("call microservice: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired token, got %d", resp.StatusCode)
	}

	body, status, err := setup.Introspect(tokenResp.AccessToken)
	if err != nil {
		t.Fatalf("introspect call: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("introspect status %d", status)
	}
	if active, _ := body["active"].(bool); active {
		t.Fatalf("expected inactive token after expiry, got %v", body["active"])
	}
}
