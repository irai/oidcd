# Token Gateway Docs

## Client SDK quick start

```go
package main

import (
    "log"
    "net/http"

    "github.com/go-chi/chi/v5"
    "oidcd/client"
)

func main() {
    validator := client.NewValidator(client.ValidatorConfig{
        Issuer:            "https://auth.example.com",
        JWKSURL:           "https://auth.example.com/.well-known/jwks.json",
        ExpectedAudiences: []string{"ai-gateway"},
    })

    r := chi.NewRouter()
    r.Use(client.RequireAuthMiddleware(validator, "ai.read"))
    r.Get("/hello", func(w http.ResponseWriter, r *http.Request) {
        claims, _ := client.ClaimsFromContext(r.Context())
        _, _ = w.Write([]byte("hello " + claims.Subject))
    })

    log.Fatal(http.ListenAndServe(":8081", r))
}
```

## OIDC flow overview

1. Browser hits `/authorize` with PKCE (`code_challenge_method=S256`).
2. Gateway reuses existing session or redirects to upstream Auth0/Entra for login.
3. After callback the gateway issues a local authorization code and refresh/access tokens via `/token`.
4. Microservices verify gateway access tokens with the SDK or JWKS endpoint and enforce scopes.
5. Refresh tokens rotate automatically; `/revoke` and `/introspect` support token management.
