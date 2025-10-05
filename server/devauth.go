package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

const debugClientID = "oidcd-debug-client"

type DebugAuthFlow struct {
	ID             string
	Provider       string
	Scope          string
	Audience       string
	State          string
	Nonce          string
	CodeVerifier   string
	CodeChallenge  string
	AuthParams     url.Values
	CreatedAt      time.Time
	Proceeded      bool
	ProviderUser   *ProviderUser
	ProviderError  string
	CallbackParams url.Values
	TokenResponse  *TokenResponse
	TokenError     string
}

type DebugAuthManager struct {
	mu    sync.RWMutex
	flows map[string]*DebugAuthFlow
}

func NewDebugAuthManager() *DebugAuthManager {
	return &DebugAuthManager{flows: make(map[string]*DebugAuthFlow)}
}

func (m *DebugAuthManager) CreateFlow(flow *DebugAuthFlow) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flows[flow.ID] = flow
}

func (m *DebugAuthManager) Get(id string) (*DebugAuthFlow, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	flow, ok := m.flows[id]
	return flow, ok
}

func (m *DebugAuthManager) MarkProceeded(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if flow, ok := m.flows[id]; ok {
		flow.Proceeded = true
	}
}

func (m *DebugAuthManager) RecordProviderResponse(id string, user *ProviderUser, providerErr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	flow, ok := m.flows[id]
	if !ok {
		return
	}
	if providerErr != "" {
		flow.ProviderError = providerErr
		return
	}
	if user != nil {
		copyUser := *user
		if copyUser.Claims != nil {
			copyUser.Claims = cloneClaims(copyUser.Claims)
		}
		flow.ProviderUser = &copyUser
	}
}

func (m *DebugAuthManager) RecordCallbackParams(id string, params url.Values) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if flow, ok := m.flows[id]; ok {
		flow.CallbackParams = cloneValues(params)
	}
}

func (m *DebugAuthManager) RecordTokenResult(id string, tokens *TokenResponse, tokenErr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	flow, ok := m.flows[id]
	if !ok {
		return
	}
	if tokenErr != "" {
		flow.TokenError = tokenErr
		return
	}
	if tokens != nil {
		copyTokens := *tokens
		flow.TokenResponse = &copyTokens
		flow.TokenError = ""
	}
}

func cloneValues(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for k, vals := range in {
		cp := make([]string, len(vals))
		copy(cp, vals)
		out[k] = cp
	}
	return out
}

func cloneClaims(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

type devAuthStep struct {
	Number int
	Title  string
	Status string
}

type kv struct {
	Key   string
	Value string
	Info  string
}

type devAuthView struct {
	Step            string
	Steps           []devAuthStep
	Providers       []string
	DefaultProvider string
	ScopeDefault    string
	AudienceDefault string
	Flow            *DebugAuthFlow
	RequestParams   []kv
	CallbackParams  []kv
	ProviderJSON    string
	TokenJSON       string
	ClaimsJSON      string
	AccessToken     string
	RefreshToken    string
	TokenError      string
	ProviderError   string
	SessionCookie   *http.Cookie
	Session         *Session
}

var devAuthTemplate = template.Must(template.New("devAuth").Funcs(template.FuncMap{
	"eq": func(a, b string) bool { return a == b },
}).Parse(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>OIDC Dev Auth Debugger</title>
<style>
body { font-family: Arial, sans-serif; margin: 2rem auto; max-width: 960px; color: #1d1d1f; }
h1 { font-size: 1.8rem; margin-bottom: 1rem; }
section { margin-bottom: 2rem; }
label { display: block; margin-bottom: 0.5rem; font-weight: 600; }
input[type=text], select { width: 100%; padding: 0.5rem; margin-bottom: 1rem; }
button { padding: 0.6rem 1.2rem; font-size: 1rem; cursor: pointer; }
.code { background: #f5f5f5; padding: 1rem; border-radius: 8px; font-family: monospace; white-space: pre-wrap; word-break: break-word; }
.steps { display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
.step { border: 1px solid #d0d0d5; border-radius: 8px; padding: 0.75rem 1rem; flex: 1 1 200px; }
.step strong { display: block; margin-bottom: 0.35rem; }
.step--done { border-color: #4caf50; background: #eaf7eb; }
.step--active { border-color: #1976d2; background: #e7f1fb; }
.step--error { border-color: #d32f2f; background: #fbeaea; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #d0d0d5; padding: 0.5rem; text-align: left; font-size: 0.95rem; }
th { background: #f0f0f5; }
small { color: #555; }
.notice { margin-top: -1rem; margin-bottom: 1.5rem; color: #555; }
</style>
</head>
<body>
<h1>Development Authentication Flow Debugger</h1>
<p class="notice">This helper walks through the authorization flow step-by-step. Available only in development mode.</p>
<div class="steps">
{{range .Steps}}
  <div class="step step--{{.Status}}">
    <strong>Step {{.Number}}</strong>
    <div>{{.Title}}</div>
  </div>
{{end}}
</div>
{{if eq .Step "index"}}
<section>
  <form method="post" action="/dev/auth/start">
    <label for="provider">Identity provider</label>
    <select id="provider" name="provider">
      {{range .Providers}}
        <option value="{{.}}" {{if eq $.DefaultProvider .}}selected{{end}}>{{.}}</option>
      {{end}}
    </select>
    <label for="scope">Scopes (space separated)</label>
    <input id="scope" name="scope" type="text" value="{{.ScopeDefault}}" />
    <label for="audience">Audience (optional)</label>
    <input id="audience" name="audience" type="text" value="{{.AudienceDefault}}" />
    <button type="submit">Start debug login</button>
  </form>
</section>
{{else if eq .Step "review"}}
<section>
  <h2>Step 2 &ndash; Review authorization request</h2>
  <p>These are the parameters that will be sent to the gateway's <code>/authorize</code> endpoint.</p>
  <table>
    <thead><tr><th>Key</th><th>Value</th><th>Explanation</th></tr></thead>
    <tbody>
    {{range .RequestParams}}
      <tr>
        <td>{{.Key}}</td>
        <td>{{.Value}}</td>
        <td>{{if .Info}}<small>{{.Info}}</small>{{end}}</td>
      </tr>
    {{end}}
    </tbody>
    </table>
  <form method="post" action="/dev/auth/flow/{{.Flow.ID}}/proceed" style="margin-top:1.5rem;">
    <button type="submit">Proceed to identity provider</button>
  </form>
</section>
<section>
  <h2>Step 3 &ndash; Complete identity provider login</h2>
  <p>After continuing, complete the login with the upstream provider in the new window. You'll be returned here automatically.</p>
</section>
{{else if eq .Step "result"}}
<section>
  <h2>Step 2 &ndash; Authorization request summary</h2>
  <table>
    <thead><tr><th>Key</th><th>Value</th><th>Explanation</th></tr></thead>
    <tbody>
    {{range .RequestParams}}
      <tr>
        <td>{{.Key}}</td>
        <td>{{.Value}}</td>
        <td>{{if .Info}}<small>{{.Info}}</small>{{end}}</td>
      </tr>
    {{end}}
    </tbody>
    </table>
</section>
<section>
  <h2>Step 3 &ndash; Identity provider response</h2>
  {{if .ProviderError}}
    <div class="step step--error">{{.ProviderError}}</div>
  {{else if .ProviderJSON}}
    <div class="code">{{.ProviderJSON}}</div>
  {{else}}
    <p>Waiting for identity provider response...</p>
  {{end}}
  {{if .CallbackParams}}
  <h3>Callback query parameters</h3>
  <table>
    <thead><tr><th>Key</th><th>Value</th></tr></thead>
    <tbody>
    {{range .CallbackParams}}
      <tr><td>{{.Key}}</td><td>{{.Value}}</td></tr>
    {{end}}
    </tbody>
  </table>
  {{end}}
</section>
<section>
  <h2>Step 4 &ndash; Gateway tokens and session</h2>
  {{if .TokenError}}
    <div class="step step--error">{{.TokenError}}</div>
  {{else if .TokenJSON}}
    <h3>Token response</h3>
    <div class="code">{{.TokenJSON}}</div>
    <h3>Access token (JWT)</h3>
    <div class="code">{{.AccessToken}}</div>
    {{if .RefreshToken}}
    <h3>Refresh token</h3>
    <div class="code">{{.RefreshToken}}</div>
    {{end}}
    {{if .ClaimsJSON}}
    <h3>Decoded access token claims</h3>
    <div class="code">{{.ClaimsJSON}}</div>
    {{end}}
    <h3>Session cookie</h3>
    {{if .SessionCookie}}
      <div class="code">Name: {{.SessionCookie.Name}}
Value: {{.SessionCookie.Value}}
Path: {{.SessionCookie.Path}}
{{if .Session}}User: {{.Session.UserID}} (provider {{.Session.IDP}})
Expires: {{.Session.ExpiresAt}}
{{end}}</div>
    {{else}}
      <p>No session cookie detected on this request.</p>
    {{end}}
  {{else}}
    <p>Waiting for token exchange...</p>
  {{end}}
</section>
{{end}}
</body>
</html>
`))

func (a *App) handleDevAuthIndex(w http.ResponseWriter, r *http.Request) {
	if !a.Config.Server.DevMode {
		http.NotFound(w, r)
		return
	}

	providers := a.devProviderList()
	view := devAuthView{
		Step:            "index",
		Providers:       providers,
		DefaultProvider: a.DefaultProvider,
		ScopeDefault:    "openid profile email",
		AudienceDefault: a.Config.Server.ServerID,
		Steps: []devAuthStep{
			{Number: 1, Title: "Configure request", Status: "active"},
			{Number: 2, Title: "Review redirect", Status: "pending"},
			{Number: 3, Title: "Identity provider", Status: "pending"},
			{Number: 4, Title: "Gateway tokens", Status: "pending"},
		},
	}
	a.renderDevAuth(w, view)
}

func (a *App) handleDevAuthStart(w http.ResponseWriter, r *http.Request) {
	if !a.Config.Server.DevMode {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	provider := strings.TrimSpace(r.FormValue("provider"))
	if provider == "" {
		provider = a.DefaultProvider
	}
	if provider != localProviderName {
		if _, ok := a.Providers[provider]; !ok {
			http.Error(w, "provider not configured", http.StatusBadRequest)
			return
		}
	}

	scope := strings.TrimSpace(r.FormValue("scope"))
	if scope == "" {
		scope = "openid profile email"
	}
	audience := strings.TrimSpace(r.FormValue("audience"))

	flowID := a.Store.NewID()
	nonce := a.Store.NewID()
	verifier, challenge, err := generatePKCE()
	if err != nil {
		http.Error(w, "pkce generation failed", http.StatusInternalServerError)
		return
	}

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", a.DebugClientID)
	params.Set("redirect_uri", a.DebugRedirect)
	params.Set("scope", scope)
	params.Set("state", flowID)
	params.Set("nonce", nonce)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")
	params.Set("idp", provider)
	if audience != "" {
		params.Set("audience", audience)
	}

	flow := &DebugAuthFlow{
		ID:            flowID,
		Provider:      provider,
		Scope:         scope,
		Audience:      audience,
		State:         flowID,
		Nonce:         nonce,
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
		AuthParams:    params,
		CreatedAt:     time.Now(),
	}
	a.Debug.CreateFlow(flow)

	http.Redirect(w, r, "/dev/auth/flow/"+flowID, http.StatusSeeOther)
}

func (a *App) handleDevAuthFlow(w http.ResponseWriter, r *http.Request) {
	if !a.Config.Server.DevMode {
		http.NotFound(w, r)
		return
	}

	flowID := chi.URLParam(r, "id")
	flow, ok := a.Debug.Get(flowID)
	if !ok {
		http.NotFound(w, r)
		return
	}

	step := "review"
	if flow.CallbackParams != nil || flow.TokenResponse != nil || flow.TokenError != "" {
		step = "result"
	}

	view := a.buildDevAuthView(flow, step, r)
	a.renderDevAuth(w, view)
}

func (a *App) handleDevAuthProceed(w http.ResponseWriter, r *http.Request) {
	if !a.Config.Server.DevMode {
		http.NotFound(w, r)
		return
	}

	flowID := chi.URLParam(r, "id")
	flow, ok := a.Debug.Get(flowID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	a.Debug.MarkProceeded(flowID)
	http.Redirect(w, r, "/authorize?"+flow.AuthParams.Encode(), http.StatusSeeOther)
}

func (a *App) handleDevAuthResult(w http.ResponseWriter, r *http.Request) {
	if !a.Config.Server.DevMode {
		http.NotFound(w, r)
		return
	}

	query := r.URL.Query()
	flowID := query.Get("state")
	if flowID == "" {
		http.Error(w, "state missing", http.StatusBadRequest)
		return
	}
	flow, ok := a.Debug.Get(flowID)
	if !ok {
		http.Error(w, "debug session expired", http.StatusBadRequest)
		return
	}

	a.Debug.RecordCallbackParams(flowID, query)

	if errParam := query.Get("error"); errParam != "" {
		description := strings.TrimSpace(query.Get("error_description"))
		msg := description
		if msg == "" {
			switch errParam {
			case "upstream_exchange":
				msg = "upstream provider exchange failed"
			case "session_create":
				msg = "session creation failed"
			case "issue_code":
				msg = "authorization code issuance failed"
			default:
				msg = errParam
			}
		}
		if flow.TokenError == "" {
			a.Debug.RecordTokenResult(flowID, nil, msg)
		}
		if flow.ProviderError == "" && errParam == "upstream_exchange" {
			a.Debug.RecordProviderResponse(flowID, nil, msg)
		}
	} else if flow.TokenResponse == nil && flow.TokenError == "" {
		code := query.Get("code")
		if code == "" {
			a.Debug.RecordTokenResult(flowID, nil, "authorization code missing in callback")
		} else {
			tokenResp, tokenErr := a.exchangeDebugCode(r, flow, code)
			a.Debug.RecordTokenResult(flowID, tokenResp, tokenErr)
		}
	}

	flow, _ = a.Debug.Get(flowID)
	view := a.buildDevAuthView(flow, "result", r)
	a.renderDevAuth(w, view)
}

func (a *App) exchangeDebugCode(r *http.Request, flow *DebugAuthFlow, code string) (*TokenResponse, string) {
	authCode, ok := a.Store.ConsumeAuthCode(code)
	if !ok {
		return nil, "authorization code not found or already used"
	}

	if authCode.CodeChallenge != "" {
		if err := verifyPKCE(authCode, flow.CodeVerifier); err != nil {
			return nil, fmt.Sprintf("pkce verification failed: %v", err)
		}
	}

	client, ok := a.Clients.Get(authCode.ClientID)
	if !ok {
		return nil, "client associated with code not found"
	}

	tokens, err := a.Tokens.MintForAuthorizationCode(r.Context(), authCode, client)
	if err != nil {
		return nil, fmt.Sprintf("mint tokens failed: %v", err)
	}

	return &tokens, ""
}

func (a *App) buildDevAuthView(flow *DebugAuthFlow, step string, r *http.Request) devAuthView {
	providers := a.devProviderList()
	steps := []devAuthStep{
		{Number: 1, Title: "Configure request", Status: "done"},
		{Number: 2, Title: "Review redirect", Status: "pending"},
		{Number: 3, Title: "Identity provider", Status: "pending"},
		{Number: 4, Title: "Gateway tokens", Status: "pending"},
	}

	switch step {
	case "index":
		steps[0].Status = "active"
	case "review":
		steps[1].Status = "active"
	default:
		steps[1].Status = "done"
		if flow.ProviderError != "" {
			steps[2].Status = "error"
		} else if flow.ProviderUser != nil || flow.CallbackParams != nil {
			steps[2].Status = "done"
		} else if flow.Proceeded {
			steps[2].Status = "active"
		}

		if flow.TokenError != "" {
			steps[3].Status = "error"
		} else if flow.TokenResponse != nil {
			steps[3].Status = "done"
		} else if flow.CallbackParams != nil {
			steps[3].Status = "active"
		}
	}

	reqParams := valuesToPairs(flow.AuthParams)
	callbackParams := valuesToPairs(flow.CallbackParams)
	notes := authorizeParamNotes(a.Config, flow)
	for i := range reqParams {
		if info, ok := notes[reqParams[i].Key]; ok {
			reqParams[i].Info = info
		}
	}

	if tenant := a.Config.Server.Providers.Entra.TenantID; tenant != "" {
		reqParams = append(reqParams, kv{
			Key:   "providers.entra.tenant_id",
			Value: tenant,
			Info:  "Value from config.yaml providers.entra.tenant_id; must match the Azure AD tenant ID in the identity provider.",
		})
	}
	if id := a.Config.Server.Providers.Entra.ClientID; id != "" {
		reqParams = append(reqParams, kv{
			Key:   "providers.entra.client_id",
			Value: id,
			Info:  "Client ID from config.yaml providers.entra.client_id; must match the registered app in the identity provider.",
		})
	}
	if secret := a.Config.Server.Providers.Entra.ClientSecret; secret != "" {
		reqParams = append(reqParams, kv{
			Key:   "providers.entra.client_secret",
			Value: maskSecret(secret),
			Info:  "Client secret from config.yaml providers.entra.client_secret (masked). Must match the secret issued by the identity provider.",
		})
	} else {
		reqParams = append(reqParams, kv{
			Key:   "providers.entra.client_secret",
			Value: "(not set)",
			Info:  "No client secret configured; provider integration must either be public or set this value in config.yaml.",
		})
	}
	if a.DebugClientSecret != "" {
		reqParams = append(reqParams, kv{
			Key:   "client.secret (masked)",
			Value: maskSecret(a.DebugClientSecret),
			Info:  "Client secret used by the gateway when exchanging codes. Stored under config.yaml clients[].client_secret.",
		})
	} else {
		reqParams = append(reqParams, kv{
			Key:   "client.secret",
			Value: "(public client; no secret)",
			Info:  "This client uses PKCE instead of a shared secret.",
		})
	}

	providerJSON := ""
	if flow.ProviderUser != nil {
		payload := map[string]any{
			"subject": flow.ProviderUser.Subject,
			"email":   flow.ProviderUser.Email,
			"name":    flow.ProviderUser.Name,
			"claims":  flow.ProviderUser.Claims,
		}
		if b, err := json.MarshalIndent(payload, "", "  "); err == nil {
			providerJSON = string(b)
		}
	}

	tokenJSON := ""
	accessToken := ""
	refreshToken := ""
	claimsJSON := ""
	var session *Session
	var cookie *http.Cookie

	if flow.TokenResponse != nil {
		if b, err := json.MarshalIndent(flow.TokenResponse, "", "  "); err == nil {
			tokenJSON = string(b)
		}
		accessToken = flow.TokenResponse.AccessToken
		refreshToken = flow.TokenResponse.RefreshToken
		if accessToken != "" {
			if claims, err := a.Tokens.ValidateAccessToken(r.Context(), accessToken); err == nil {
				if b, err := json.MarshalIndent(claims, "", "  "); err == nil {
					claimsJSON = string(b)
				}
			}
		}
		cookie, _ = r.Cookie(sessionCookieName)
		if sess, _ := a.Sessions.Fetch(r); sess != nil {
			session = sess
		}
	}

	view := devAuthView{
		Step:            step,
		Steps:           steps,
		Providers:       providers,
		DefaultProvider: flow.Provider,
		ScopeDefault:    flow.Scope,
		AudienceDefault: flow.Audience,
		Flow:            flow,
		RequestParams:   reqParams,
		CallbackParams:  callbackParams,
		ProviderJSON:    providerJSON,
		TokenJSON:       tokenJSON,
		ClaimsJSON:      claimsJSON,
		AccessToken:     accessToken,
		RefreshToken:    refreshToken,
		TokenError:      flow.TokenError,
		ProviderError:   flow.ProviderError,
		SessionCookie:   cookie,
		Session:         session,
	}

	return view
}

func (a *App) renderDevAuth(w http.ResponseWriter, view devAuthView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := devAuthTemplate.Execute(w, view); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *App) debugResultURL(state, reason string) string {
	base := a.DebugRedirect
	if base == "" {
		base = "/dev/auth/result"
	}
	vals := url.Values{}
	if state != "" {
		vals.Set("state", state)
	}
	if reason != "" {
		vals.Set("error", reason)
	}
	encoded := vals.Encode()
	if encoded == "" {
		return base
	}
	if strings.Contains(base, "?") {
		return base + "&" + encoded
	}
	return base + "?" + encoded
}

func (a *App) devProviderList() []string {
	providers := make([]string, 0, len(a.Providers)+1)
	providers = append(providers, localProviderName)
	for name := range a.Providers {
		providers = append(providers, name)
	}
	sort.Strings(providers)
	return providers
}

func valuesToPairs(vals url.Values) []kv {
	if vals == nil {
		return nil
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]kv, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, kv{Key: k, Value: strings.Join(vals[k], ", ")})
	}
	return pairs
}

func authorizeParamNotes(cfg Config, flow *DebugAuthFlow) map[string]string {
	notes := map[string]string{}

	set := func(key, msg string) { notes[key] = msg }

	set("response_type", "Fixed value required by OAuth2; the gateway only supports the authorization code flow.")
	set("client_id", "Client identifier presented to the gateway. Defaults to the first entry under config.yaml clients[].client_id and must match the identity provider app registration.")
	set("redirect_uri", "Redirect target where the gateway sends the browser after login. The debugger uses /dev/auth/result and appends it to the active client's redirect list at runtime; register this URI with the identity provider when testing externally.")
	set("scope", "Space-separated scopes requested from the gateway. Configure defaults under config.yaml clients.scopes; upstream provider must allow these scopes.")
	set("state", "Random per-request value generated by the gateway to protect against CSRF. No configuration required, but the provider returns it unchanged.")
	set("nonce", "Random nonce for ID token replay protection. No configuration needed, but upstream must echo it in the ID token.")
	set("code_challenge", "PKCE challenge derived from the code_verifier the debugger stores. No configuration required; verifier never leaves the gateway.")
	set("code_challenge_method", "Always S256 to enforce PKCE. No configuration needed; upstream must support S256.")
	set("idp", "Selected provider key. Must match a provider defined in config.yaml providers.*, and align with the IdP registration (tenant, client ID, redirect).")
	set("audience", fmt.Sprintf("Target resource audience. Defaults to config.yaml tokens.audience_default (%s). Ensure upstream understands this value if it validates audience.", cfg.Server.ServerID))

	if flow != nil {
		set("client_id", fmt.Sprintf("Client ID %q taken from config.yaml (first client entry). Must match the identity provider application.", flow.AuthParams.Get("client_id")))
		set("redirect_uri", fmt.Sprintf("Debugger callback %s. Ensure this URI appears in config.yaml clients[].redirect_uris and is registered in the identity provider.", flow.AuthParams.Get("redirect_uri")))
		if flow.Audience != "" && flow.Audience != cfg.Server.ServerID {
			set("audience", fmt.Sprintf("Target audience %q requested. Must be configured for the client in config.yaml and allowed by the upstream resource.", flow.Audience))
		}
		if ten := cfg.Server.Providers.Entra.TenantID; ten != "" {
			set("idp", fmt.Sprintf("Using provider %q (tenant %s). Tenant ID must match the IdP directory configuration.", flow.Provider, ten))
		}
	}

	return notes
}

func generatePKCE() (string, string, error) {
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

func maskSecret(secret string) string {
	if secret == "" {
		return ""
	}
	if len(secret) <= 8 {
		return secret
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}
