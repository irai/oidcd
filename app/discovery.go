package app

import "strings"

// DiscoveryDocument is a simple alias for discovery metadata.
type DiscoveryDocument map[string]any

// BuildDiscoveryDocument constructs the OIDC discovery document.
func BuildDiscoveryDocument(cfg Config) DiscoveryDocument {
	issuer := strings.TrimSuffix(cfg.Server.PublicURL, "/")
	return DiscoveryDocument{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"introspection_endpoint":                issuer + "/introspect",
		"revocation_endpoint":                   issuer + "/revoke",
		"end_session_endpoint":                  issuer + "/logout",
	}
}
