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

* `GET /.well-known/openid-configuration` — discovery document.
* `GET /.well-known/jwks.json` (alias `/jwks.json`) — public keys for JWT validation.
* `GET /authorize` — Auth Code + PKCE; supports `scope`, `state`, `nonce`, optional `aud`/`resource`, `idp=auth0|entra`.
* `GET /callback/{idp}` — handle upstream redirect; exchange code → ID token; create/refresh local session.
* `POST /token` — grants: `authorization_code`, `refresh_token` (rotation), `client_credentials`.
* `GET /userinfo` — return minimal user claims.
* `POST /introspect` — RFC 7662.
* `POST /revoke` — RFC 7009.
* Optional `POST /logout` — clear session cookie and revoke session.

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

## 8. Microservice Design: Validating/Rejecting API Calls

**Core Principles**

* Accept only **gateway‑issued** JWTs.
* Validate **signature**, `iss`, **acceptable `aud`**, `exp/nbf/iat` (with clock skew), and **required scopes**.
* Apply **resource‑level authorization**: tenant ownership, roles, ABAC/RBAC checks.

**SDK Usage (Go)**

* Import the `/client` package shipped by the gateway repo.
* Initialize a `Validator` with gateway `issuer`, `jwks_url`, and `expected audiences`.
* Use HTTP middleware to enforce auth and scopes.

**Example (chi) — Protect routes and check scope**

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

**Common Rejection Reasons**

* `401` — Missing/invalid Bearer token; signature mismatch; wrong `iss`.
* `403` — Valid token but insufficient `scope`; `aud` not allowed; tenant mismatch.

**Performance**

* JWKS cached in memory with ETag/Cache‑Control; refresh on `kid` miss.
* Prefer short AT TTLs + refresh rotation in BFF.

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

* **Server**: issuer, dev/prod mode, HTTP/HTTPS addresses, domain names, TLS mode (autocert/certmagic/manual), HSTS, CORS, proxy trust.
* **Keys**: algorithm (RS256), rotation interval, persistent key path in prod.
* **Providers**: Auth0 & Entra: issuer URL, client id/secret.
* **Clients**: public/confidential, redirect URIs, allowed scopes/audiences.
* **Tokens**: access TTL (5–10m), refresh TTL (e.g., 30d), rotation on.
* **Sessions**: TTL (e.g., 12h), sliding window optional.

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
