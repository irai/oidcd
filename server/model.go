package server

import "time"

// Session captures a logged-in browser session bound to a cookie.
type Session struct {
	ID        string
	UserID    string
	IDP       string
	AuthTime  time.Time
	ExpiresAt time.Time
	AMR       []string
	ACR       []string
}

// AuthorizationCode represents a short-lived code issued to a client.
type AuthorizationCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	SessionID           string
	UserID              string
	IDP                 string
	Audience            string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	Used                bool
}

// RefreshToken represents a stored refresh token for rotation tracking.
type RefreshToken struct {
	ID        string
	ClientID  string
	UserID    string
	Scope     string
	Audience  string
	IDP       string
	IssuedAt  time.Time
	ExpiresAt time.Time
	ParentID  string
	Revoked   bool
	SessionID string
}

// Client records OAuth client metadata.
type Client struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	Scopes       []string
	Audiences    []string
	Public       bool
}

// TokenPair bundles access and refresh token responses.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	TokenType    string
	Scope        string
}

// UserInfo contains minimal claims returned from /userinfo.
type UserInfo struct {
	Subject string            `json:"sub"`
	Email   string            `json:"email,omitempty"`
	Name    string            `json:"name,omitempty"`
	Custom  map[string]any    `json:"-"`
}

// ProviderUser consolidates identity data from upstream IdPs.
type ProviderUser struct {
	Subject string
	Email   string
	Name    string
	Claims  map[string]any
}
