package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Routes constructs the HTTP router with all OAuth/OIDC endpoints.
func (a *App) Routes() http.Handler {
	// If proxy is configured, use it as the main handler with OIDC endpoints mounted
	if a.Proxy != nil {
		return a.buildProxyRouter()
	}

	// Standard OIDC-only router
	return a.buildOIDCRouter()
}

func (a *App) buildOIDCRouter() http.Handler {
	r := chi.NewRouter()

	r.Use(RequestIDMiddleware)
	r.Use(LoggingMiddleware(a.Logger))
	r.Use(RecoveryMiddleware(a.Logger, a.Config.Server.DevMode))
	r.Use(CORSMiddleware(a.Config.InferCORSOrigins()))
	if !a.Config.Server.DevMode {
		r.Use(SecurityHeadersMiddleware())
	}

	r.Get("/.well-known/openid-configuration", a.handleDiscovery)
	r.Get("/.well-known/jwks.json", a.handleJWKS)
	r.Get("/jwks.json", a.handleJWKS)

	r.Get("/authorize", a.handleAuthorize)
	r.Get("/callback/{idp}", a.handleCallback)

	if a.Config.Server.DevMode {
		r.Get("/dev/auth", a.handleDevAuthIndex)
		r.Post("/dev/auth/start", a.handleDevAuthStart)
		r.Get("/dev/auth/flow/{id}", a.handleDevAuthFlow)
		r.Post("/dev/auth/flow/{id}/proceed", a.handleDevAuthProceed)
		r.Get("/dev/auth/result", a.handleDevAuthResult)
	}

	r.Post("/token", a.handleToken)
	r.Get("/userinfo", a.handleUserInfo)
	r.Post("/introspect", a.handleIntrospect)
	r.Post("/revoke", a.handleRevoke)
	r.Post("/logout", a.handleLogout)

	return r
}

func (a *App) buildProxyRouter() http.Handler {
	r := chi.NewRouter()

	r.Use(RequestIDMiddleware)
	r.Use(LoggingMiddleware(a.Logger))
	r.Use(RecoveryMiddleware(a.Logger, a.Config.Server.DevMode))
	r.Use(CORSMiddleware(a.Config.InferCORSOrigins()))
	if !a.Config.Server.DevMode {
		r.Use(SecurityHeadersMiddleware())
	}

	// Mount OIDC endpoints - these always take precedence
	r.Get("/.well-known/openid-configuration", a.handleDiscovery)
	r.Get("/.well-known/jwks.json", a.handleJWKS)
	r.Get("/jwks.json", a.handleJWKS)

	r.Get("/authorize", a.handleAuthorize)
	r.Get("/callback/{idp}", a.handleCallback)

	if a.Config.Server.DevMode {
		r.Get("/dev/auth", a.handleDevAuthIndex)
		r.Post("/dev/auth/start", a.handleDevAuthStart)
		r.Get("/dev/auth/flow/{id}", a.handleDevAuthFlow)
		r.Post("/dev/auth/flow/{id}/proceed", a.handleDevAuthProceed)
		r.Get("/dev/auth/result", a.handleDevAuthResult)
	}

	r.Post("/token", a.handleToken)
	r.Get("/userinfo", a.handleUserInfo)
	r.Post("/introspect", a.handleIntrospect)
	r.Post("/revoke", a.handleRevoke)
	r.Post("/logout", a.handleLogout)

	// Catch-all: proxy all other requests based on Host header
	r.HandleFunc("/*", a.Proxy.ServeHTTP)

	return r
}
