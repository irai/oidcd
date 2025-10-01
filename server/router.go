package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Routes constructs the HTTP router with all OAuth/OIDC endpoints.
func (a *App) Routes() http.Handler {
	r := chi.NewRouter()

	r.Use(RequestIDMiddleware)
	r.Use(LoggingMiddleware(a.Logger))
	r.Use(RecoveryMiddleware(a.Logger, a.Config.Server.DevMode))
	r.Use(CORSMiddleware(a.Config.Server.CORS))
	if !a.Config.Server.DevMode {
		r.Use(SecurityHeadersMiddleware(a.Config.Server.TLS.HSTSMaxAge))
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
