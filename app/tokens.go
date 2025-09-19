package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AccessTokenClaims captures the JWT claims we mint and validate.
type AccessTokenClaims struct {
	Scope    string `json:"scope"`
	ClientID string `json:"client_id"`
	IDP      string `json:"idp,omitempty"`
	jwt.RegisteredClaims
}

// TokenResponse matches OAuth token endpoint payloads.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// TokenService signs and validates gateway tokens.
type TokenService struct {
	issuer        string
	accessTTL     time.Duration
	refreshTTL    time.Duration
	rotateRefresh bool
	store         *InMemoryStore
	jwks          *JWKSManager
	logger        *slog.Logger
	audDefault    string
}

// NewTokenService constructs a TokenService.
func NewTokenService(cfg Config, store *InMemoryStore, jwks *JWKSManager, logger *slog.Logger) *TokenService {
	return &TokenService{
		issuer:        strings.TrimSuffix(cfg.Server.PublicURL, "/"),
		accessTTL:     cfg.Tokens.AccessTTL,
		refreshTTL:    cfg.Tokens.RefreshTTL,
		rotateRefresh: cfg.Tokens.RotateRefresh,
		store:         store,
		jwks:          jwks,
		logger:        logger,
		audDefault:    cfg.Tokens.AudienceDefault,
	}
}

// MintForAuthorizationCode exchanges an auth code for tokens.
func (ts *TokenService) MintForAuthorizationCode(ctx context.Context, code AuthorizationCode, client *Client) (TokenResponse, error) {
	if !client.ValidateScopes(code.Scope) {
		return TokenResponse{}, fmt.Errorf("invalid scope")
	}

	audience := client.ResolveAudience(code.Audience, ts.defaultAudience())
	subject := code.UserID

	accessClaims := ts.buildAccessClaims(subject, client.ClientID, audience, code.Scope, code.IDP)
	accessToken, err := ts.sign(accessClaims)
	if err != nil {
		return TokenResponse{}, err
	}

	resp := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(ts.accessTTL.Seconds()),
		Scope:       code.Scope,
	}

	if ts.refreshTTL > 0 {
		rt := ts.newRefreshToken(code.SessionID, client.ClientID, subject, code.Scope, audience, code.IDP, "")
		ts.store.SaveRefreshToken(rt)
		resp.RefreshToken = rt.ID
	}

	return resp, nil
}

// MintForRefreshToken rotates refresh tokens and issues a new access token.
func (ts *TokenService) MintForRefreshToken(ctx context.Context, token string, client *Client) (TokenResponse, error) {
	rt, ok := ts.store.GetRefreshToken(token)
	if !ok || rt.Revoked {
		return TokenResponse{}, fmt.Errorf("refresh token invalid")
	}
	if rt.ClientID != client.ClientID {
		return TokenResponse{}, fmt.Errorf("refresh token client mismatch")
	}
	if time.Now().After(rt.ExpiresAt) {
		ts.store.DeleteRefreshToken(rt.ID)
		return TokenResponse{}, fmt.Errorf("refresh token expired")
	}

	accessClaims := ts.buildAccessClaims(rt.UserID, client.ClientID, rt.Audience, rt.Scope, rt.IDP)
	accessToken, err := ts.sign(accessClaims)
	if err != nil {
		return TokenResponse{}, err
	}

	resp := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(ts.accessTTL.Seconds()),
		Scope:       rt.Scope,
	}

	if ts.rotateRefresh {
		ts.store.DeleteRefreshToken(rt.ID)
		rt.Revoked = true
		ts.store.SaveRefreshToken(rt)

		newRT := ts.newRefreshToken(rt.SessionID, client.ClientID, rt.UserID, rt.Scope, rt.Audience, rt.IDP, rt.ID)
		ts.store.SaveRefreshToken(newRT)
		resp.RefreshToken = newRT.ID
	} else {
		resp.RefreshToken = rt.ID
	}

	return resp, nil
}

// MintForClientCredentials handles machine tokens.
func (ts *TokenService) MintForClientCredentials(ctx context.Context, client *Client, scope, audience string) (TokenResponse, error) {
	if client.Public {
		return TokenResponse{}, fmt.Errorf("public clients cannot use client_credentials")
	}
	if scope != "" && !client.ValidateScopes(scope) {
		return TokenResponse{}, fmt.Errorf("invalid scope")
	}

	aud := client.ResolveAudience(audience, ts.defaultAudience())
	claims := ts.buildAccessClaims(client.ClientID, client.ClientID, aud, scope, "")
	token, err := ts.sign(claims)
	if err != nil {
		return TokenResponse{}, err
	}

	return TokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int64(ts.accessTTL.Seconds()),
		Scope:       scope,
	}, nil
}

// ValidateAccessToken parses and validates a minted JWT.
func (ts *TokenService) ValidateAccessToken(ctx context.Context, token string) (*AccessTokenClaims, error) {
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()})}
	tok, err := jwt.ParseWithClaims(token, &AccessTokenClaims{}, ts.jwks.Keyfunc, opts...)
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(*AccessTokenClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	if claims.Issuer != ts.issuer {
		return nil, fmt.Errorf("invalid issuer")
	}
	if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time) {
		return nil, fmt.Errorf("token expired")
	}
	if ts.store.JTIBlacklisted(claims.ID) {
		return nil, fmt.Errorf("token revoked")
	}
	return claims, nil
}

// Introspect returns RFC 7662 metadata.
func (ts *TokenService) Introspect(token string, client *Client) map[string]any {
	claims, err := ts.ValidateAccessToken(context.Background(), token)
	if err != nil {
		return map[string]any{"active": false}
	}

	aud := ""
	if len(claims.Audience) > 0 {
		aud = claims.Audience[0]
	}
	active := map[string]any{
		"active":     true,
		"scope":      claims.Scope,
		"client_id":  claims.ClientID,
		"sub":        claims.Subject,
		"aud":        aud,
		"iss":        claims.Issuer,
		"token_type": "access_token",
	}
	if claims.ExpiresAt != nil {
		active["exp"] = claims.ExpiresAt.Time.Unix()
	}
	if claims.IssuedAt != nil {
		active["iat"] = claims.IssuedAt.Time.Unix()
	}
	return active
}

// Revoke revokes refresh tokens or blacklists access tokens by JTI.
func (ts *TokenService) Revoke(ctx context.Context, client *Client, token string) {
	rt, ok := ts.store.GetRefreshToken(token)
	if ok {
		if rt.ClientID == client.ClientID {
			rt.Revoked = true
			ts.store.SaveRefreshToken(rt)
		}
		return
	}

	tok, err := jwt.ParseWithClaims(token, &AccessTokenClaims{}, ts.jwks.Keyfunc)
	if err != nil {
		return
	}
	claims, ok := tok.Claims.(*AccessTokenClaims)
	if !ok || !tok.Valid {
		return
	}
	exp := time.Now().Add(ts.accessTTL)
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Time
	}
	ts.store.BlacklistJTI(claims.ID, exp)
}

func (ts *TokenService) sign(claims AccessTokenClaims) (string, error) {
	if claims.IssuedAt == nil {
		now := jwt.NewNumericDate(time.Now())
		claims.IssuedAt = now
	}
	if claims.ExpiresAt == nil {
		exp := jwt.NewNumericDate(time.Now().Add(ts.accessTTL))
		claims.ExpiresAt = exp
	}
	if claims.ID == "" {
		claims.ID = ts.store.NewID()
	}
	claims.Issuer = ts.issuer

	mapClaims, err := claimsToMap(claims)
	if err != nil {
		return "", err
	}
	token, _, err := ts.jwks.Sign(mapClaims)
	return token, err
}

func (ts *TokenService) buildAccessClaims(sub, clientID, audience, scope, idp string) AccessTokenClaims {
	return AccessTokenClaims{
		Scope:    scope,
		ClientID: clientID,
		IDP:      idp,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ts.accessTTL)),
		},
	}
}

func (ts *TokenService) newRefreshToken(sessionID, clientID, userID, scope, audience, idp, parent string) RefreshToken {
	id := ts.store.NewID()
	return RefreshToken{
		ID:        id,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		Audience:  audience,
		IDP:       idp,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(ts.refreshTTL),
		ParentID:  parent,
		SessionID: sessionID,
	}
}

func (ts *TokenService) defaultAudience() string {
	if ts.audDefault != "" {
		return ts.audDefault
	}
	return ""
}

func verifyPKCE(code AuthorizationCode, verifier string) error {
	if verifier == "" {
		return errors.New("code_verifier required")
	}
	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	if expected != code.CodeChallenge {
		return fmt.Errorf("pkce verification failed")
	}
	return nil
}

func claimsToMap(claims AccessTokenClaims) (jwt.MapClaims, error) {
	b, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	var out jwt.MapClaims
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
