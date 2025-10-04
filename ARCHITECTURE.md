# OIDC Gateway Architecture

**Scope:** This document defines the architecture, flows, and implementation guidance for a Go-based OIDC/OAuth2 **gateway** that acts as the edge entry point for web and API traffic, performs TLS termination, delegates end-user login to upstream IdPs (Auth0, Microsoft Entra ID), maintains local sessions, and mints first‑party access tokens for downstream microservices. It also defines how to build microservices and BFF (Backend‑For‑Frontend) applications that integrate with the gateway.

---

## 1. Goals & Non‑Goals

**Goals**

* Single entry point for browser and API traffic.
* Enforce HTTPS at the edge (TLS 1.2+), easy prod setup via ACME/Let’s Encrypt; simple dev mode.
* Delegate user authentication to upstream IdPs; gateway keeps its own session for SSO.
* Gateway issues **first‑party JWT access tokens** and refresh tokens.
* Provide a **client SDK** for microservices to validate tokens and scopes.
* Support public (PKCE) and confidential clients; client‑credentials for service accounts.

**Non‑Goals**

* Implement a full UI for login (handled by upstream IdPs).
* Replace per‑service authorization logic—gateway standardizes identity/claims; fine‑grained authorization remains in services.

---

## 2. Roles & Components

* **Gateway (OIDC Provider):** Authorization Server (AS) for clients; Relying Party to upstream IdPs.
* **Upstream IdP:** Auth0 / Microsoft Entra ID (Azure AD). Hosts login UI, token endpoint for upstream code exchange.
* **Microservices:** Resource servers that trust gateway JWTs via JWKS; enforce `aud`, `scope`, tenancy/ownership rules.
* **BFF (Backend‑For‑Frontend):** Web app backend that uses the gateway as its OP; holds the browser session; exchanges code → tokens server‑side.

---

## 3. Edge TLS Termination

**Prod**

* Terminate TLS in the gateway using ACME (autocert/certmagic).
* Enforce HTTPS only; redirect HTTP→HTTPS; add HSTS header.
* Optionally run behind CDN/ingress; honor `X‑Forwarded‑Proto` when `trust_proxy_headers=true`.

**Dev**

* `dev_mode=true` → bind to `127.0.0.1:8080` over HTTP only.
* Cookies: `Secure=false`, `SameSite=Lax`.

**TLS Minimums**

* TLS ≥ 1.2, strong cipher suites.
* Rotate certificates automatically; persist ACME cache.

---

## 4. OIDC/OAuth2 Endpoints (Gateway)

### Standard OIDC Endpoints

* `GET /.well-known/openid-configuration` — discovery document.
* `GET /.well-known/jwks.json` (alias `/jwks.json`) — public keys for JWT validation.
* `GET /authorize` — Auth Code + PKCE; supports `scope`, `state`, `nonce`, optional `aud`/`resource`, `idp=auth0|entra`.
* `GET /callback/{idp}` — handle upstream redirect; exchange code → ID token; create/refresh local session.
* `POST /token` — grants: `authorization_code`, `refresh_token` (rotation), `client_credentials`.
* `GET /userinfo` — return minimal user claims.
* `POST /introspect` — RFC 7662.
* `POST /revoke` — RFC 7009.
* Optional `POST /logout` — clear session cookie and revoke session.

### Reverse Proxy Endpoints

When proxy routes are configured, the gateway also handles:

* **Host-based routing** — All requests are routed based on the HTTP `Host` header.
* **Automatic authentication redirect** — If `require_auth: true` and no valid session exists, gateway redirects to `/authorize` with state preserving original URL.
* **OAuth callback handling** — `GET /callback/{idp}` also handles proxy authentication callbacks, creating sessions and redirecting back to original URL.
* **Session-based authentication** — All proxy routes share the same session cookie (configured via `cookie_domain`).

**Example Flow:**
1. User accesses `https://demo-app.example.com/dashboard`
2. Gateway matches route by host, checks for session
3. No session → redirect to `GET /authorize?client_id=gateway-proxy&redirect_uri=...&state=<encoded_original_url>`
4. After authentication → redirect to `GET /callback/entra?code=...&state=...`
5. Gateway creates session, sets cookie, redirects back to `https://demo-app.example.com/dashboard`
6. Subsequent requests include session cookie → proxied directly to backend

---

## 5. Session Model (Gateway)

**Cookie**: `gw_session` (HttpOnly; `Secure` in prod; `SameSite=Lax` dev / `Strict` prod).

**Fields**: `session_id`, `user_id`, `idp`, `auth_time`, `expires_at`, optional `amr/acr`, anti‑CSRF secret for HTML consent.

**Behavior**

* `/authorize` checks for a valid local session first. If valid, immediately creates an authorization code for the client (no upstream redirect). If missing/expired, redirect to the chosen IdP.
* `/callback/{idp}` performs upstream token exchange and creates/refreshes the local session.
* Sliding expiration (optional): extend session TTL on activity, up to a max absolute lifetime.

---

## 6. Token Model

**ID Token (JWT RS256) — OIDC Specification**

When `openid` scope is requested, the gateway returns an ID token containing:

* Header: `alg=RS256`, `kid=<current key>`.
* Standard claims: `iss=<gateway issuer>`, `sub=<stable user id>`, `aud=<client_id>`, `iat`, `exp (5–10m)`, `nonce` (if provided).
* Profile claims: `email`, `name`, `preferred_username` (sourced from upstream IdP user profile).
* Custom claims: `idp` (identity provider name: `auth0`, `entra`, or `local`).

The ID token is intended for the client application to learn about the authenticated user. It is **not** used for API authorization.

**Access Token (JWT RS256)**

* Header: `alg=RS256`, `kid=<current key>`.
* Claims: `iss=<gateway issuer>`, `sub=<stable user id>`, `aud=<service or suite>`, `scope=<space-delimited>`, `iat`, `exp (5–10m)`, `jti`, `client_id`, `idp`.
* Used for authorizing API requests to downstream microservices.

**Refresh Token**

* Opaque token with rotation (server store); rotation + replay detection.
* Used to obtain new access tokens without re-authenticating the user.

**User Profile Storage**

* The gateway stores minimal user profile information (`email`, `name`) in memory after upstream IdP authentication.
* Profile data is keyed by `<idp>:<subject>` and retrieved when minting ID tokens.
* Profile information is also available via the `/userinfo` endpoint.

**JWKS & Keys**

* Publish current + previous keys at `/.well-known/jwks.json`.
* Key rotation job; maintain grace period for old keys.

---

## 7. Authentication & Authorization Flows

**End‑User (Auth Code + PKCE)**

1. Browser hits Web App (BFF) protected page.
2. BFF redirects to `GET /authorize` on the gateway with `scope=openid profile email`.
3. Gateway **reuses session** if valid; otherwise redirects to IdP login.
4. After IdP login, `GET /callback/{idp}` on gateway; gateway:
   - Exchanges code with upstream IdP
   - Retrieves user profile (email, name) from upstream IdP
   - Stores user profile in memory
   - Creates local gateway session
   - Issues authorization code for the client
5. BFF exchanges code at `/token` → gets **ID Token (JWT)**, **Access Token (JWT)**, and **Refresh Token**.
   - ID Token contains user identity claims (email, name, preferred_username)
   - Access Token is used for API authorization
6. BFF sets its own session cookie and calls microservices with the Access Token.

**Service‑to‑Service (Client Credentials)**

* Confidential client presents client id/secret at `/token` grant `client_credentials`; gets service‑scoped Access Token.

**Refresh Rotation**

* `/token` with `grant_type=refresh_token` rotates refresh tokens; invalidate old token (replay detection).

---

## 8. Three Integration Patterns

The gateway supports three distinct patterns for protecting applications and services:

### 8.1. BFF (Backend-For-Frontend) Pattern

**Use Case:** Traditional web applications with server-side rendering or Next.js/React apps with a backend.

**How it Works:**
1. Browser requests protected page → BFF detects no session
2. BFF redirects to gateway `/authorize` with PKCE
3. Gateway reuses session if valid; otherwise redirects to IdP login
4. After authentication, gateway redirects back to BFF with authorization code
5. BFF exchanges code for tokens (ID token, access token, refresh token)
6. BFF creates its own session cookie and stores tokens server-side
7. BFF calls microservices using the access token as Bearer token

**BFF Security:**
- Require PKCE (S256) for public clients
- Validate `state` and `nonce`; short-lived authorization codes
- Strict redirect URI allow-list
- CSRF protection for state-changing endpoints (double submit or SameSite=Strict)
- Tokens never exposed to browser; httpOnly session cookies only

**When to Use:**
- Building traditional web applications
- Need server-side session management
- Want to keep tokens completely off the browser
- Building new applications from scratch

---

### 8.2. Microservice Pattern (Direct JWT Validation)

**Use Case:** Internal APIs and microservices that need fine-grained control over authentication.

**How it Works:**
1. Client (BFF or another service) obtains JWT from gateway
2. Client includes JWT in `Authorization: Bearer <token>` header
3. Microservice validates JWT signature using gateway's JWKS
4. Microservice checks `iss`, `aud`, `exp`, and required scopes
5. Microservice applies resource-level authorization (tenant ownership, roles, etc.)

**Core Principles:**
- Accept only **gateway-issued** JWTs
- Validate **signature**, `iss`, **acceptable `aud`**, `exp/nbf/iat` (with clock skew), and **required scopes**
- Apply **resource-level authorization**: tenant ownership, roles, ABAC/RBAC checks

**SDK Usage (Go):**
- Import the `/client` package shipped by the gateway repo
- Initialize a `Validator` with gateway `issuer`, `jwks_url`, and `expected audiences`
- Use HTTP middleware to enforce auth and scopes

**Example (chi) — Protect routes and check scope:**

```go
v := client.NewValidator(client.ValidatorConfig{
  Issuer: "https://auth.example.com",
  JWKSURL: "https://auth.example.com/.well-known/jwks.json",
  ExpectedAudiences: []string{"ai-gateway", "svc-orders"},
})

r := chi.NewRouter()
r.Use(client.RequireAuthMiddleware(v, "orders.read"))

r.Get("/orders/{id}", func(w http.ResponseWriter, r *http.Request) {
  // Claims available in context; perform tenant/resource checks here.
  // If additional scopes needed for certain endpoints, chain another middleware or check in handler.
})
```

**Common Rejection Reasons:**
- `401` — Missing/invalid Bearer token; signature mismatch; wrong `iss`
- `403` — Valid token but insufficient `scope`; `aud` not allowed; tenant mismatch

**Performance:**
- JWKS cached in memory with ETag/Cache-Control; refresh on `kid` miss
- Prefer short AT TTLs + refresh rotation in BFF

**When to Use:**
- Building internal microservices
- Need fine-grained scope and audience validation
- Want service-to-service authentication
- Services built in different languages/frameworks

---

### 8.3. Reverse Proxy Pattern (Zero-Auth Edge Protection)

**Use Case:** Protect existing applications or services without modifying their code. Ideal for legacy systems, third-party apps, or rapid prototyping.

**How it Works:**
1. User accesses protected domain (e.g., `demo-app.example.com`)
2. Gateway checks for valid session cookie
3. If no session, gateway redirects to IdP for authentication
4. After authentication, gateway creates session and sets cookie
5. Gateway proxies request to backend, optionally injecting JWT and user claims as headers
6. Backend receives authenticated request with user context (no auth code needed)

**Configuration Example:**

```yaml
proxy:
  routes:
    # Public route - no authentication required
    - host: demo-public.example.com
      target: http://backend1:3000
      require_auth: false
      preserve_host: false

    # Protected route - authentication required
    - host: demo-app.example.com
      target: http://backend2:3000
      require_auth: true
      preserve_host: false

    # Advanced - inject JWT and user claims as headers
    - host: demo-api.example.com
      target: http://backend3:3000
      require_auth: true
      inject_jwt: true
      jwt_header_name: X-Auth-Token
      inject_user_claims: true
      claims_headers:
        email: X-User-Email
        name: X-User-Name
        sub: X-User-ID
```

**Proxy Route Options:**
- `host`: Hostname to match (from HTTP Host header)
- `target`: Backend service URL
- `require_auth`: If true, enforce authentication before proxying
- `required_scopes`: Optional list of scopes required for access
- `strip_prefix`: Remove URL prefix before proxying
- `preserve_host`: Keep original Host header when proxying
- `timeout`: Custom timeout for this route
- `inject_jwt`: Automatically inject JWT as header
- `jwt_header_name`: Header name for JWT (default: `Authorization`)
- `inject_as_bearer`: If true, format as `Bearer <token>`
- `inject_user_claims`: Extract claims from JWT and inject as headers
- `claims_headers`: Map of claim name to header name
- `skip_paths`: Paths that bypass authentication (e.g., health checks)
- `auth_redirect_url`: Custom redirect URL after authentication

**Authentication Flow:**
1. Request to protected route without session → redirect to gateway `/authorize`
2. Gateway authenticates user via IdP
3. Gateway creates session with cookie (shared across all proxy routes via `cookie_domain`)
4. Gateway redirects back to original URL
5. Subsequent requests include session cookie → proxied directly to backend

**Security Features:**
- Session cookies with configurable domain (supports subdomain sharing)
- Automatic session validation before each proxied request
- Optional JWT injection with standard Bearer format
- User claim injection as custom headers
- Scope-based access control per route
- Path-based authentication bypass for health checks

**When to Use:**
- Protecting legacy applications without code changes
- Rapid prototyping and demos
- Migrating existing services to authenticated architecture
- Third-party applications that can't integrate OIDC
- Microservices that can handle user context from headers
- Centralized authentication policy enforcement

**Backend Integration:**
The backend service receives requests with optional injected headers:
- `Authorization: Bearer <jwt>` (if `inject_jwt: true` and `inject_as_bearer: true`)
- `X-User-Email: user@example.com` (if `inject_user_claims: true`)
- `X-User-Name: John Doe` (if `inject_user_claims: true`)
- `X-User-ID: auth0|123456` (if `inject_user_claims: true`)

Backend can:
1. **Trust the headers** (gateway is the only entry point)
2. **Validate the JWT** using the gateway's JWKS (defense in depth)
3. **Use user context** for business logic, logging, or authorization

---

### Pattern Comparison

| Feature | BFF | Microservice | Reverse Proxy |
|---------|-----|-------------|---------------|
| **Authentication Code** | In BFF layer | In each service | None (gateway handles) |
| **Token Type** | Session cookies | Bearer JWT | Both supported |
| **Backend Changes** | Medium | Medium-High | None to minimal |
| **Best For** | Web applications | Internal APIs | Legacy/third-party apps |
| **Security Model** | Session-based | Token validation | Centralized at edge |
| **Flexibility** | Low | High | Medium |
| **Setup Complexity** | Medium | Medium | Low (config only) |
| **Migration Effort** | New BFF build | Code changes | Config only |
| **Production Ready** | ✅ Yes | ✅ Yes | ✅ Yes |

**Decision Guide:**
- 👉 Use **BFF** if you're building a traditional web application with server-side session management
- 👉 Use **Microservice** if you need fine-grained control, service-to-service auth, or multi-language support
- 👉 Use **Reverse Proxy** if you want centralized auth with zero backend code changes

---

## 9. BFF Application Design & Workflows

**Why BFF**

* Keep tokens off the browser; the BFF holds sensitive tokens and sets an httpOnly session cookie.

**Workflow**

1. **Unauthenticated request** → BFF redirects to `GET /authorize` with PKCE, `state`, `nonce`.
2. **Gateway session reuse** may immediately return a code; otherwise IdP login occurs.
3. **Callback to BFF** with gateway code → BFF posts to `/token` (back‑channel), obtains AT/RT.
4. **BFF session** created; store user id, token metadata server‑side. Set secure httpOnly cookie.
5. **API calls** from BFF to microservices include **Bearer AT** in `Authorization` header.
6. **Refresh**: BFF rotates refresh tokens on schedule or 401 replay; handle retries conservatively.
7. **Logout**: BFF clears its cookie; optionally hit gateway `/logout` to kill gateway session.

**BFF Security**

* Require PKCE (S256) for public clients.
* Validate `state` and `nonce`; short‑lived authorization codes.
* Strict redirect URI allow‑list.
* CSRF protection for state‑changing endpoints (double submit or SameSite=Strict).

---

## 10. Configuration (Summary)

* **Server**: public URL (issuer), dev/prod mode, HTTP/HTTPS listen addresses, cookie domain (for subdomain sharing), TLS config, CORS, proxy trust.
* **TLS**: mode (autocert/certmagic/manual), domains list, cache directory, ACME email, HSTS max age, minimum TLS version.
* **Keys**: algorithm (RS256), rotation interval, persistent key path in prod.
* **Providers**: Auth0 & Entra: issuer URL, client id/secret, tenant ID (for Entra).
* **Clients**: public/confidential, redirect URIs, allowed scopes/audiences.
* **Tokens**: access TTL (5–10m), refresh TTL (e.g., 30d), rotation on, default audience.
* **Sessions**: TTL (e.g., 12h), sliding window optional.
* **Proxy**: routes with host-based routing, authentication requirements, JWT/claims injection, scope enforcement.

### Configuration Example

```yaml
server:
  public_url: http://localhost:8080
  dev_listen_addr: 0.0.0.0:8080
  http_listen_addr: :80
  https_listen_addr: :443
  dev_mode: true
  cookie_domain: ""  # Empty for localhost, or .example.com for subdomain sharing
  tls:
    mode: autocert
    domains:
      - localhost
      - auth.example.com
      - app1.example.com
      - app2.example.com
    cache_dir: ./.certs
    email: admin@example.com
    hsts_max_age: 15552000
    min_version: "1.2"
  trust_proxy_headers: false
  cors:
    client_origin_urls:
      - http://localhost:3001
    allowed_headers:
      - Authorization
      - Content-Type
    allowed_methods:
      - GET
      - POST
      - OPTIONS

keys:
  jwks_path: ""
  rotate_interval: 168h0m0s
  alg: RS256

clients:
  - client_id: webapp
    client_secret: ""
    redirect_uris:
      - http://localhost:3001/callback
    scopes:
      - openid
      - profile
      - email
    audiences:
      - ai-gateway

  - client_id: gateway-proxy
    client_secret: ""
    redirect_uris:
      - http://localhost:8080/callback/entra
    scopes:
      - openid
      - profile
      - email
    audiences:
      - proxy

providers:
  default: entra
  entra:
    issuer: https://login.microsoftonline.com/common/v2.0
    client_id: "your-client-id"
    client_secret: "your-client-secret"
    tenant_id: "your-tenant-id"

tokens:
  access_ttl: 10m0s
  refresh_ttl: 720h0m0s
  rotate_refresh: true
  audience_default: ai-gateway

sessions:
  ttl: 12h0m0s

proxy:
  routes:
    - host: demo-public.example.com
      target: http://backend1:3000
      require_auth: false

    - host: demo-app.example.com
      target: http://backend2:3000
      require_auth: true
      inject_jwt: true
      inject_as_bearer: true
```

### Environment Variable Overrides

Key configuration values can be overridden via environment variables:

* `OIDCD_SERVER_PUBLIC_URL` — Override server.public_url
* `OIDCD_SERVER_DEV_LISTEN_ADDR` — Override server.dev_listen_addr
* `OIDCD_SERVER_HTTP_LISTEN_ADDR` — Override server.http_listen_addr
* `OIDCD_SERVER_HTTPS_LISTEN_ADDR` — Override server.https_listen_addr
* `OIDCD_SERVER_DEV_MODE` — Override server.dev_mode (true/false)
* `OIDCD_SERVER_TLS_DOMAINS` — Override server.tls.domains (comma-separated)
* `OIDCD_SERVER_TLS_CACHE_DIR` — Override server.tls.cache_dir
* `OIDCD_SERVER_TLS_EMAIL` — Override server.tls.email
* `OIDCD_SERVER_TLS_MODE` — Override server.tls.mode
* `OIDCD_SERVER_CORS_CLIENT_ORIGIN_URLS` — Override server.cors.client_origin_urls (comma-separated)
* `OIDCD_KEYS_JWKS_PATH` — Override keys.jwks_path
* `OIDCD_TOKENS_ACCESS_TTL` — Override tokens.access_ttl
* `OIDCD_TOKENS_REFRESH_TTL` — Override tokens.refresh_ttl
* `OIDCD_TOKENS_ROTATE_REFRESH` — Override tokens.rotate_refresh (true/false)

---

## 11. Operational Guidance

**Runbooks**

* **Key rotation**: ensure JWKS publishes previous keys during rollover; monitor microservice validation errors.
* **Incident: token leak**: reduce AT TTL; revoke refresh tokens by jti; rotate signing keys; invalidate sessions; audit logs.
* **Scaling**: stateless handlers; externalize session/refresh stores (e.g., Redis/Postgres) beyond dev.
* **Observability**: structured logs (slog), metrics (Prom/OTEL), audit trails with minimal PII.

---

## 12. Error Handling Patterns

* Normalize OAuth errors at `/token` and `/authorize` with RFC‑compliant fields (`error`, `error_description`).
* Microservices return `401/403` with problem‑details JSON; avoid leaking internals.
* BFF retries on **token‑expired** once after refresh; otherwise surface a 401 and redirect to sign‑in.

---

## 13. Testing & Verification

* **Dev loop**: run gateway in dev mode; register loopback redirect URIs with IdPs.
* **Unit tests**: JWT claims and signature validation, refresh rotation, session reuse.
* **E2E flow**: headless browser (or curl) across: BFF → /authorize → IdP → callback → /token → API call.
* **Test client**: A reference implementation is provided in `cmd/client/` demonstrating the full OIDC flow.

**Test Client Application**

A sample web application is included to demonstrate and verify the OIDC integration:

* Location: `cmd/client/main.go`
* Demonstrates: Authorization Code flow with PKCE, ID token validation, user profile display
* Run with Docker: `docker-compose up --build`
* Access at: `http://localhost:3001` (when using Docker Compose)

The test client:
1. Redirects users to the gateway `/authorize` endpoint
2. Handles the callback with authorization code
3. Exchanges code for tokens (ID token, access token, refresh token)
4. Validates the ID token
5. Displays user information from token claims (email, name, preferred_username)

**Example curl: obtain token (client credentials)**

```bash
curl -X POST https://auth.example.com/token \
 -H 'Content-Type: application/x-www-form-urlencoded' \
 -d 'grant_type=client_credentials&client_id=svcA&client_secret=***&scope=ai.read%20orders.read&audience=svc-orders'
```

---

## 14. Security Checklist

* [ ] HTTPS only in prod; HSTS enabled; TLS ≥ 1.2.
* [ ] PKCE (S256) for public clients; short‑lived codes.
* [ ] Validate `state`, `nonce`; single‑use codes; replay protection.
* [ ] Short AT TTL; refresh rotation; revoke on suspicion.
* [ ] Strict `aud` and `scope` checks in services.
* [ ] Key rotation with overlapping JWKS; `kid` pinned; time‑bounded deprecation.
* [ ] Minimal PII in logs; access logs include request\_id; redact tokens.
* [ ] Rate limit `/token` endpoint; bot/abuse protections as needed.

---

## 15. Appendix

**IdP Registration (Entra ID)**

* Register app; add redirect URIs: dev `http://127.0.0.1:8080/callback/entra`, prod `https://auth.example.com/callback/entra`.
* Enable ID tokens; create client secret; configure issuer `https://login.microsoftonline.com/<TENANT_ID>/v2.0`.

**IdP Registration (Auth0)**

* Create application; allowed callback URLs (dev/prod); copy domain, client id/secret; set issuer `https://<TENANT>.auth0.com/`.

**BFF Cookie Domains**

* Prefer same‑site domain patterns (e.g., `app.example.com`, `auth.example.com`). Don’t rely on third‑party cookies.

**Device/CLI Flow (optional)**

* Add Device Authorization Flow for CLI/dev tools that cannot handle browser redirects.

---

### Quick Start for Developers

**Using Docker Compose (Recommended for Testing)**

1. Configure `config.yaml` with your Microsoft Entra ID credentials
2. Run `docker-compose up --build`
3. Access the test client at `http://localhost:3001`
4. Click "Login with OIDC" to test the full authentication flow
5. Verify ID token claims include email, name, and preferred_username

**Manual Development Setup**

1. Run the gateway in dev mode; set Auth0/Entra credentials in `config.yaml`.
2. In your microservice, import the client SDK and protect routes with `RequireAuthMiddleware` + required scopes.
3. In your BFF, implement the OIDC code flow against the gateway and keep tokens server‑side; set an httpOnly session cookie.
4. Validate everything locally using the test client (`cmd/client/`) or sample curl commands.
