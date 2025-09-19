package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
)

// ValidatorConfig configures the token validator.
type ValidatorConfig struct {
	Issuer            string
	JWKSURL           string
	ExpectedAudiences []string
	CacheTTL          time.Duration
	HTTPClient        *http.Client
	IntrospectionURL  string
	IntrospectionAuth string
}

// Validator verifies gateway-signed JWT access tokens.
type Validator struct {
	cfg    ValidatorConfig
	client *http.Client
	mu     sync.RWMutex
	cache  jwksCache
}

type jwksCache struct {
	set      jose.JSONWebKeySet
	fetched  time.Time
	expires  time.Time
	etag     string
}

// Claims is a simplified view of validated token claims.
type Claims struct {
	Subject   string
	Issuer    string
	Audiences []string
	Scopes    []string
	ClientID  string
	TokenID   string
	ExpiresAt time.Time
	IssuedAt  time.Time
	Raw       map[string]any
}

// NewValidator creates a validator with sane defaults.
func NewValidator(cfg ValidatorConfig) *Validator {
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	return &Validator{cfg: cfg, client: client}
}

// Validate downloads JWKS if necessary and validates the token.
func (v *Validator) Validate(ctx context.Context, rawToken string) (*Claims, error) {
	if rawToken == "" {
		return nil, errors.New("token required")
	}

	set, err := v.ensureJWKS(ctx, "")
	if err != nil {
		return nil, err
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithLeeway(30*time.Second),
	)

	claims := jwt.MapClaims{}
	tok, err := parser.ParseWithClaims(rawToken, claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		key := findKey(set, kid)
		if key == nil {
			// Force refresh on kid miss
			if _, err := v.ensureJWKS(ctx, kid); err == nil {
				key = findKey(v.currentSet(), kid)
			}
		}
		if key == nil {
			return nil, fmt.Errorf("signing key not found")
		}
		return key.Key, nil
	})
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("token invalid")
	}

	return v.mapClaims(claims)
}

// HasScopes ensures the claims include the required scopes.
func (v *Validator) HasScopes(claims *Claims, required ...string) error {
	if len(required) == 0 {
		return nil
	}
	have := make(map[string]struct{}, len(claims.Scopes))
	for _, sc := range claims.Scopes {
		have[sc] = struct{}{}
	}
	for _, need := range required {
		if _, ok := have[need]; !ok {
			return fmt.Errorf("missing scope %s", need)
		}
	}
	return nil
}

// RequireAuth middleware validates tokens and injects claims into context.
func RequireAuth(v *Validator, requiredScopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			parts := strings.SplitN(auth, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				http.Error(w, "invalid authorization header", http.StatusUnauthorized)
				return
			}

			claims, err := v.Validate(r.Context(), parts[1])
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			if err := v.HasScopes(claims, requiredScopes...); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey{}, claims)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAuthMiddleware is an alias to fit chi middleware signatures.
func RequireAuthMiddleware(v *Validator, requiredScopes ...string) func(http.Handler) http.Handler {
	return RequireAuth(v, requiredScopes...)
}

// ClaimsFromContext retrieves claims attached by the middleware.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsKey{}).(*Claims)
	return claims, ok
}

type claimsKey struct{}

func (v *Validator) ensureJWKS(ctx context.Context, kid string) (jose.JSONWebKeySet, error) {
	v.mu.RLock()
	cache := v.cache
	v.mu.RUnlock()

	if cache.set.Keys != nil && time.Now().Before(cache.expires) && kid == "" {
		return cache.set, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	if cache.etag != "" {
		req.Header.Set("If-None-Match", cache.etag)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		cache.expires = time.Now().Add(v.cfg.CacheTTL)
		v.mu.Lock()
		v.cache = cache
		v.mu.Unlock()
		return cache.set, nil
	}
	if resp.StatusCode != http.StatusOK {
		return jose.JSONWebKeySet{}, fmt.Errorf("jwks fetch failed: %s", resp.Status)
	}

	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return jose.JSONWebKeySet{}, err
	}

	cache = jwksCache{set: set, fetched: time.Now(), etag: resp.Header.Get("ETag")}
	cache.expires = cache.fetched.Add(maxCacheDuration(resp.Header.Get("Cache-Control"), v.cfg.CacheTTL))

	v.mu.Lock()
	v.cache = cache
	v.mu.Unlock()

	return set, nil
}

func (v *Validator) currentSet() jose.JSONWebKeySet {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.cache.set
}

func (v *Validator) mapClaims(mc jwt.MapClaims) (*Claims, error) {
	raw := make(map[string]any, len(mc))
	for k, val := range mc {
		raw[k] = val
	}

	iss, _ := mc["iss"].(string)
	if v.cfg.Issuer != "" && iss != v.cfg.Issuer {
		return nil, fmt.Errorf("issuer mismatch")
	}

	sub, _ := mc["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("sub missing")
	}

	audiences := normalizeAudience(mc["aud"])
	if len(v.cfg.ExpectedAudiences) > 0 {
		if !audienceAllowed(audiences, v.cfg.ExpectedAudiences) {
			return nil, fmt.Errorf("audience rejected")
		}
	}

	scopeStr, _ := mc["scope"].(string)
	scopes := strings.Fields(scopeStr)

	clientID, _ := mc["client_id"].(string)
	jid, _ := mc["jti"].(string)

	exp := parseUnix(mc["exp"])
	iat := parseUnix(mc["iat"])

	return &Claims{
		Subject:   sub,
		Issuer:    iss,
		Audiences: audiences,
		Scopes:    scopes,
		ClientID:  clientID,
		TokenID:   jid,
		ExpiresAt: exp,
		IssuedAt:  iat,
		Raw:       raw,
	}, nil
}

func findKey(set jose.JSONWebKeySet, kid string) *jose.JSONWebKey {
	for _, k := range set.Keys {
		if kid == "" || k.KeyID == kid {
			key := k
			return &key
		}
	}
	return nil
}

func audienceAllowed(aud, expected []string) bool {
	if len(aud) == 0 {
		return false
	}
	for _, a := range aud {
		for _, exp := range expected {
			if a == exp {
				return true
			}
		}
	}
	return false
}

func normalizeAudience(val any) []string {
	switch v := val.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		res := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				res = append(res, s)
			}
		}
		return res
	case []string:
		return v
	default:
		return nil
	}
}

func parseUnix(val any) time.Time {
	switch v := val.(type) {
	case float64:
		return time.Unix(int64(v), 0)
	case json.Number:
		i, _ := v.Int64()
		return time.Unix(i, 0)
	case int64:
		return time.Unix(v, 0)
	default:
		return time.Time{}
	}
}

func maxCacheDuration(header string, fallback time.Duration) time.Duration {
	if fallback <= 0 {
		fallback = 5 * time.Minute
	}
	parts := strings.Split(header, ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && strings.EqualFold(kv[0], "max-age") {
			if secs, err := time.ParseDuration(kv[1] + "s"); err == nil {
				return secs
			}
		}
	}
	return fallback
}

// Introspect optionally calls the gateway introspection endpoint.
func (v *Validator) Introspect(ctx context.Context, token string) (map[string]any, error) {
	if v.cfg.IntrospectionURL == "" {
		return nil, errors.New("introspection not configured")
	}

	form := url.Values{}
	form.Set("token", token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.cfg.IntrospectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if v.cfg.IntrospectionAuth != "" {
		req.Header.Set("Authorization", v.cfg.IntrospectionAuth)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection failed: %s", resp.Status)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return body, nil
}
