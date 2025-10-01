# Go OIDC Token Gateway

A lightweight OIDC/OAuth2 authorization server that fronts upstream IdPs (Auth0 or Microsoft Entra) and mints first-party JWT access tokens for internal microservices. It acts as an edge gateway with TLS termination, reverse proxy capabilities, and centralized authentication.

## Features
- **Edge Gateway**: Single entry point with TLS termination and host-based reverse proxy
- **Authentication**: Authorization Code + PKCE relay to Auth0/Entra with local session reuse
- **Token Management**: RS256 JWT signing, refresh token rotation, JWKS publishing
- **OIDC Endpoints**: `/authorize`, `/token`, `/userinfo`, `/jwks.json`, `/introspect`, `/revoke`, discovery metadata
- **SDK & Examples**: Go client SDK for token validation + working integration examples

## Three Integration Patterns

This gateway supports three common integration patterns:

### 1. **BFF (Backend-For-Frontend)** - Web Applications
For web apps that need user login. The BFF handles OAuth flow server-side and maintains HTTP-only session cookies.

**Example:** `cmd/client/` - Web application with Microsoft 365 login

**Use when:** Building web applications with user authentication

### 2. **Microservice** - JWT Token Validation
For backend APIs that validate JWT tokens on each request using the client SDK.

**Example:** `cmd/backend/` - API service that validates and displays JWT claims

**Use when:** Building internal APIs that need to verify authenticated requests

### 3. **Reverse Proxy** - Gateway-Protected Services
For services accessed through the gateway's reverse proxy with automatic authentication.

**Configuration:** Host-based routing with optional JWT validation at the gateway

**Use when:** Services should be protected at the edge without implementing auth themselves

> **📘 See [AI_INTEGRATION_GUIDE.md](AI_INTEGRATION_GUIDE.md) for detailed integration instructions**

## Quick Start with Docker Compose

The fastest way to test the OIDC gateway with Microsoft 365 is using Docker Compose:

### Prerequisites
1. Docker and Docker Compose installed
2. Microsoft Entra ID app registration (see below)

### Microsoft Entra ID Setup

1. Go to [Azure Portal](https://portal.azure.com) → **Azure Active Directory** → **App registrations**
2. Create a new app registration or use an existing one
3. Under **Authentication**, add these redirect URIs:
   - `http://localhost:8080/callback/entra` (for the gateway)
4. Under **Certificates & secrets**, create a new client secret
5. Note your **Application (client) ID** and **Directory (tenant) ID**

### Configuration

Create or update `config.yaml` with your Entra credentials:

```yaml
server:
  public_url: http://localhost:8080
  dev_listen_addr: 0.0.0.0:8080
  dev_mode: true
  cors:
    client_origin_urls:
      - http://localhost:3001

clients:
  - client_id: "webapp"
    client_secret: ""
    redirect_uris:
      - http://localhost:3001/callback
    scopes: ["openid", "profile", "email"]
    audiences: ["ai-gateway"]

providers:
  default: "entra"
  entra:
    issuer: "https://login.microsoftonline.com/common/v2.0"
    tenant_id: "YOUR_TENANT_ID"
    client_id: "YOUR_ENTRA_APP_CLIENT_ID"
    client_secret: "YOUR_ENTRA_APP_CLIENT_SECRET"
```

### Running the Stack

Start both the gateway and test client:

```bash
docker-compose up --build
```

This starts:
- **OIDC Gateway** on `http://localhost:8080`
- **Test Client App** on `http://localhost:3001`

### Testing the OIDC Flow

1. Open your browser to `http://localhost:3001`
2. Click "Login with OIDC"
3. You'll be redirected to Microsoft 365 for authentication
4. After login, you'll see your username, email, and full JWT claims
5. Click "View Full Profile" to see all token details

### Architecture

```
Browser <-> Client App (port 3001) <-> OIDC Gateway (port 8080) <-> Microsoft Entra ID
```

The test client demonstrates:
- OAuth 2.0 Authorization Code flow with PKCE
- JWT token validation
- Extracting user information from ID token claims (email, name, preferred_username)

### Docker Commands

View logs:
```bash
docker-compose logs -f          # All services
docker-compose logs -f oidcd    # Gateway only
docker-compose logs -f client   # Client only
```

Stop services:
```bash
docker-compose down
```

## Local Development (Without Docker)

### Getting Started

1. Run `token-gateway` without an existing config to launch the guided setup, or copy `config.example.yaml` to `config.yaml` and update issuer/clients/providers manually.

2. Register redirect URIs with your IdP (development defaults):
   - `http://127.0.0.1:8080/callback/auth0`
   - `http://127.0.0.1:8080/callback/entra`

3. Build and run:
   ```bash
   go build -o token-gateway .
   ./token-gateway config.yaml
   ```

   Or run directly:
   ```bash
   go run . config.yaml
   ```

   The gateway listens on `http://127.0.0.1:8080` in dev mode. When no upstream provider credentials are supplied, dev mode falls back to a built-in `local` user so the authorization code flow can complete without Auth0/Entra.

   Runtime usage accepts either the `-config` flag or a positional argument:
   ```bash
   token-gateway -config ./config.yaml
   token-gateway ./config.yaml
   ```

### What `clients:` Means
- Entries under `clients:` represent OAuth/OIDC applications that call `/authorize` and `/token`—for example your web app, SPA, CLI, or BFF that redirects users for login. Each registration lists its redirect URIs, permitted scopes, and target audiences.
- Downstream microservices are resource servers. They do **not** appear under `clients:` because they never request tokens; instead they validate the JWTs issued to the registered clients using the Go SDK in `/client` or the `/introspect` endpoint.

Guided setup prompt cheat sheet:
- **Gateway public URL** – external base URL for OIDC endpoints.
- **Gateway dev listen address** – host:port the dev server binds to (`127.0.0.1:8080` by default).
- **Client CORS origin URLs** – comma-separated list of browser origins allowed to call the gateway.
- **Client OAuth ID** – the `client_id` your front end will use in authorize/token requests.
- **Client redirect URI** – the callback URL the gateway redirects to after login.

### Example Authorization Request
```
https://auth.example.com/authorize?response_type=code&client_id=webapp&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&scope=openid%20profile%20email&state=STATE123&nonce=NONCE123&code_challenge=BASE64URL_SHA256_VERIFIER&code_challenge_method=S256&idp=auth0
```

### Token Endpoint
```bash
curl -X POST https://auth.example.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "redirect_uri=https://app.example.com/callback" \
  -d "client_id=webapp" \
  -d "code_verifier=VERIFIER"
```

### Introspect and Revoke
```bash
curl -u machine-client:secret https://auth.example.com/introspect -d "token=ACCESS_TOKEN"
curl -u machine-client:secret https://auth.example.com/revoke -d "token=REFRESH_TOKEN"
```

## Client SDK Usage
```go
import "oidcd/client"

validator := client.NewValidator(client.ValidatorConfig{
    Issuer:            "https://auth.example.com",
    JWKSURL:           "https://auth.example.com/.well-known/jwks.json",
    ExpectedAudiences: []string{"ai-gateway"},
})
router.Use(client.RequireAuthMiddleware(validator, "ai.read"))
```
See `docs/README.md` for a complete example and context helpers.

## TLS & Deployment
- **Development**: HTTP on `127.0.0.1:8080`, insecure cookies disabled. Ephemeral keys unless `keys.jwks_path` is set.
- **Production**: Autocert handles ACME/LetsEncrypt certificates. Port `:80` redirects to HTTPS and serves ACME challenges, `:443` serves the gateway with strict TLS 1.2+ and HSTS.

## Directory Layout
```
main.go                  # OIDC gateway server entrypoint (TLS + process wiring)
server/                  # Core: router, handlers, storage, sessions, tokens, jwks, proxy
client/                  # SDK for microservices (validator + middleware)
cmd/
  client/                # Example: BFF pattern (web app with login)
  backend/               # Example: Microservice pattern (JWT validation)
AI_INTEGRATION_GUIDE.md  # Integration guide for AI assistants
```

## Token Claims

### ID Token (OIDC)
When the `openid` scope is requested, the gateway returns an ID token containing:
- Standard claims: `iss`, `sub`, `aud`, `exp`, `iat`, `nonce`
- Profile claims: `email`, `name`, `preferred_username` (from upstream IdP)
- Custom claims: `idp` (identity provider name)

### Access Token (JWT)
Access tokens contain:
- Standard claims: `iss`, `sub`, `aud`, `exp`, `iat`, `jti`
- Custom claims: `scope`, `client_id`, `idp`

All tokens are signed with RS256 and can be validated using the JWKS endpoint at `/.well-known/jwks.json`.
