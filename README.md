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

### 3. **Reverse Proxy** - Gateway-Protected Services *(Enhanced)*
For services accessed through the gateway's reverse proxy with automatic authentication and JWT injection.

**Configuration:** Host-based routing with intelligent authentication detection, JWT token injection, and user claims mapping

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

---

## Enhanced Reverse Proxy Authentication 🚀

The OIDC gateway provides **enhanced reverse proxy capabilities** that automatically handle authentication and inject JWT tokens into forwarded requests, enabling **zero-authentication backend services**.

### Overview

The enhanced proxy provides **zero-authentication backend services** by:
1. **Automatically detecting** authentication method (Bearer token vs Session cookies)
2. **Validating user authorization** against upstream IdP scopes
3. **Injecting JWT tokens and user claims** into HTTP headers
4. **Handling authentication redirects** intelligently for browsers vs APIs

### Quick Start ⚡

#### Minimal Configuration
```yaml
proxy:
  routes:
    # Simple authenticated service - intelligent defaults apply
    - host: "api.example.local"
      target: "http://backend-service:3000"
      require_auth: true
```

The gateway automatically:
- ✅ Detects Bearer tokens or session cookies
- ✅ Injects JWT tokens as `X-Auth-Token` header  
- ✅ Injects user claims as `X-User-*` headers
- ✅ Skips authentication for `/health`, `/metrics` paths
- ✅ Returns JSON errors for API calls, redirects for browsers

#### Backend Service Implementation
```go
func handleProtectedAPI(w http.ResponseWriter, r *http.Request) {
    // Gateway has already authenticated the user!
    userID := r.Header.Get("X-User-ID")
    userEmail := r.Header.Get("X-User-Email")
    
    response := map[string]string{
        "message": "Protected data",
        "user_id": userID,
        "user_email": userEmail,
    }
    
    json.NewEncoder(w).Encode(response)
}
```

### Features 🎯

#### 1. Intelligent Authentication Detection
- **Bearer Token**: Detected from `Authorization` header
- **Session Cookie**: Uses existing gateway session (`gw_session`)
- **Auto-fallback**: Smart detection based on request patterns

#### 2. Automatic JWT Injection
Injects gateway-issued JWTs containing:
- **User ID**: Stable identifier from upstream IdP
- **Scopes**: Validated permissions from upstream IdP  
- **Audience**: Target service hostname
- **Short lifetime**: 10 minutes for security

#### 3. User Claims Injection
Maps upstream IdP claims to HTTP headers:
```
X-User-ID: user123
X-User-Email: john.doe@company.com
X-User-Name: John Doe
X-Auth-Token: eyJhbGciOiJSUzI1NiJ9...
X-Auth-Type: bearer
X-User-Scopes: admin.read admin.write
```

#### 4. Smart Path Exclusions
Automatically skips authentication for:
- `/health`, `/healthz`, `/status`
- `/metrics`, `/prometheus`
- `/favicon.ico`, `/robots.txt`
- `/static/*`, `/assets/*`

#### 5. Intelligent Error Handling
- **API Requests**: Returns JSON errors with status codes
- **Browser Requests**: Redirects to authentication flow
- **Scope Validation**: Returns `403 Forbidden` with details

### Configuration Options ⚙️

#### Basic Configuration
```yaml
proxy:
  routes:
    - host: "api.example.local"
      target: "http://backend:3000"
      require_auth: true
      # Automatic: inject_jwt=true, inject_user_claims=true
```

#### Advanced Configuration
```yaml
proxy:
  routes:
    - host: "admin.example.local"
      target: "http://admin-backend:3000"
      require_auth: true
      required_scopes: ["admin.read", "admin.write"]
      
      # JWT Injection
      inject_jwt: true
      jwt_header_name: "X-Admin-JWT"
      
      # User Claims Injection  
      inject_user_claims: true
      claims_headers:
        email: "X-Admin-Email"
        name: "X-Admin-Name"
        idp: "X-Identity-Provider"
      
      # Special Behavior
      inject_as_bearer: true  # Overwrite Authorization header
      auth_redirect_url: "/login"
      skip_paths: ["/health", "/debug"]
```

### Available Configuration Options

| Setting | Default | Description |
|---------|---------|-------------|
| `require_auth` | `false` | Enable authentication for this route |
| `inject_jwt` | `true` (if auth required) | Inject JWT token in headers |
| `jwt_header_name` | `"X-Auth-Token"` | Name of JWT injection header |
| `inject_user_claims` | `true` (if auth required) | Inject user claims as headers |
| `claims_headers` | Auto-mapped | Custom claim-to-header mappings |
| `inject_as_bearer` | `false` | Also inject as `Authorization: Bearer` |
| `required_scopes` | `[]` | Scopes required from upstream IdP |
| `skip_paths` | `[]` | Additional paths to exclude from auth |
| `auth_redirect_url` | `"/authorize"` | Custom authentication redirect |

### Authentication Flow 🌊

#### 1. Bearer Token Flow (API Services)
```
Client → Gateway → Backend Service
   ↓         ↓          ↓
  Bearer   Validate   Process with
   Token    JWT      injected claims
```

#### 2. Session Cookie Flow (Web Apps)
```
Browser → Gateway → Backend Service  
   ↓          ↓          ↓
Session   Validate   Process with
 Cookie   Session   injected claims
```

#### 3. Unauthenticated Flow
```
Request → Gateway → Authentication Check → Redirect/Error
   ↓                                              ↑
Service                              /authorize or JSON error
```

### Backend Service Patterns 📋

#### Pattern 1: Zero Authentication Code
```go
// Perfect for internal services
func handleAPI(w http.ResponseWriter, r *http.Request) {
    userID := r.Header.Get("X-User-ID")
    // All authentication handled at gateway
}
```

#### Pattern 2: Optional JWT Validation
```go
// Additional security layer
func handleSecureAPI(w http.ResponseWriter, r *http.Request) {
    jwtToken := r.Header.Get("X-Auth-Token")
    if jwtToken != "" {
        // Validate gateway JWT for extra security
        claims, err := validateJWT(jwtToken)
        if err != nil {
            http.Error(w, "JWT invalid", http.StatusUnauthorized)
            return
        }
    }
}
```

#### Pattern 3: Scope-Based Authorization
```go
// Use injected scopes for fine-grained access
func handleAdminAPI(w http.ResponseWriter, r *http.Request) {
    scopes := r.Header.Get("X-User-Scopes")
    if !strings.Contains(scopes, "admin.write") {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
}
```

### Example Services 🛠️

See the example services in `examples/proxy-backend/` that demonstrate:
- Receiving injected authentication headers
- Handling different authentication types
- Processing user claims and scopes
- Working with gateway-issued JWTs

### Security Benefits 🔒

1. **Centralized Authentication**: All auth logic in gateway
2. **Short-lived Tokens**: 10-minute JWT lifetime
3. **Scope Validation**: Enforced at gateway level
4. **Audit Trail**. Centralized authentication logs
5. **Token Rotation**: JWKs with key rotation support

### Testing 🧪

#### Test with curl
```bash
# Authenticate via browser first to get session cookie
open http://localhost:8080/authorize

# Test authenticated request
curl -H "Host: api.example.local" http://localhost:8080/api/protected

# Test with Bearer token
curl -H "Authorization: Bearer <token>" \
     -H "Host: api.example.local" \
     http://localhost:8080/api/protected
```

#### Expected Response Headers
```
X-User-ID: entra:user123
X-User-Email: john.doe@company.com
X-Auth-Token: eyJhbGciOiJSUzI1NiJ9...
X-Auth-Type: bearer
X-User-Scopes: admin.read admin.write
```

### Migration Guide 📈

#### From Manual Authentication
1. Remove JWT validation code from backend services
2. Replace `Authorization: Bearer` validation with header reading
3. Configure gateway proxy routes
4. Test with provided examples

#### Legacy Service Support
For services expecting `Authorization: Bearer` headers:
```yaml
proxy:
  routes:
    - host: "legacy.example.local"
      target: "http://legacy-service:3000"
      require_auth: true
      inject_as_bearer: true  # Maintains existing behavior
```

This enhancement provides a seamless transition to gateway-first authentication while maintaining compatibility with existing services.
