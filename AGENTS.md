# AI Agent Guide: Docker Compose Testing & Development

This document provides guidance for AI agents (LLMs) working with this OIDC gateway repository, specifically focused on understanding the Docker Compose setup, testing workflows, and common troubleshooting patterns.

---

## Overview

This repository implements an OIDC/OAuth2 gateway with three integration patterns:
1. **BFF (Backend-For-Frontend)** - Session-based web app authentication
2. **Microservice** - Direct JWT validation using client SDK
3. **Reverse Proxy** - Zero-auth edge protection (NEW pattern)

The Docker Compose setup demonstrates all three patterns in a single local environment.

---

## Docker Compose Architecture

### Service Topology

```
┌─────────────────────────────────────────────────────────────┐
│                       Docker Network: oidc-net               │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐                                            │
│  │   oidcd      │  Port 8080 (gateway)                       │
│  │  (gateway)   │  - OIDC provider endpoints                 │
│  └──────┬───────┘  - Reverse proxy handler                   │
│         │          - Session management                       │
│         │                                                     │
│  ┌──────▼───────┐                                            │
│  │   client     │  Port 3001 (BFF pattern demo)              │
│  │   (webapp)   │  - Demonstrates BFF authentication         │
│  └──────────────┘  - Session cookies, PKCE flow              │
│                                                               │
│  ┌──────────────┐                                            │
│  │  backend1    │  Internal 3000 (microservice pattern)      │
│  │ (public API) │  - No auth required (demo)                 │
│  └──────────────┘  - Shows public service routing            │
│                                                               │
│  ┌──────────────┐                                            │
│  │  backend2    │  Internal 3000 (microservice pattern)      │
│  │ (protected)  │  - Requires JWT validation                 │
│  └──────────────┘  - Uses client SDK                         │
│                                                               │
│  ┌──────────────┐                                            │
│  │proxy-backend │  Port 3002 (reverse proxy pattern demo)    │
│  │ (zero-auth)  │  - No authentication code                  │
│  └──────────────┘  - Receives injected headers from gateway  │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Key Configuration Files

1. **`docker-compose.yml`** - Service orchestration
2. **`config.yaml`** - Gateway configuration (MUST exist, no longer uses `config.example.yaml`)
3. **`Dockerfile`** - Gateway container build
4. **`cmd/client/Dockerfile`** - BFF test client
5. **`cmd/backend/Dockerfile`** - Microservice backends
6. **`examples/proxy-backend/Dockerfile`** - Reverse proxy demo backend

---

## Critical Configuration Patterns

### 1. Microsoft Entra ID (Azure AD) Integration

**Key Learning**: Entra ID has strict redirect URI requirements:
- ✅ Allows `http://localhost:*` (any port on localhost)
- ❌ Rejects `http://<domain>:*` unless using HTTPS
- 📌 Error: `AADSTS500117: The reply uri specified in the request isn't using a secure scheme`

**Solution for Local Development**:
```yaml
server:
  public_url: http://localhost:8080  # Use localhost, NOT custom domain
  cookie_domain: ""                   # Empty = use request host
```

**Production Setup**:
```yaml
server:
  public_url: https://auth.example.com
  cookie_domain: .example.com  # Share cookies across subdomains
  tls:
    mode: autocert
    domains:
      - auth.example.com
      - app1.example.com
      - app2.example.com
```

### 2. Proxy Route Configuration

**Host-Based Routing**:
Proxy routes match on the HTTP `Host` header. For local testing with custom domains:

```yaml
proxy:
  routes:
    # Public route - no authentication
    - host: demo-xero.dev.nexxia.com.au
      target: http://backend1:3000
      require_auth: false
      preserve_host: false

    # Protected route - requires authentication
    - host: demo-kb.dev.nexxia.com.au
      target: http://backend2:3000
      require_auth: true
      preserve_host: false

    # Advanced - inject user context as headers
    - host: demo-salesforce.dev.nexxia.com.au
      target: http://proxy-backend:3002
      require_auth: true
      preserve_host: false
```

**Testing with Custom Domains**:
Add to `/etc/hosts` (Linux/Mac) or `C:\Windows\System32\drivers\etc\hosts` (Windows):
```
127.0.0.1 demo-xero.dev.nexxia.com.au
127.0.0.1 demo-kb.dev.nexxia.com.au
127.0.0.1 demo-salesforce.dev.nexxia.com.au
```

Access via: `http://demo-salesforce.dev.nexxia.com.au:8080`

### 3. Client Configuration

**Gateway Proxy Client** (for reverse proxy pattern):
```yaml
clients:
  - client_id: gateway-proxy
    client_secret: ""  # Public client, no secret needed
    redirect_uris:
      - http://localhost:8080/callback/entra
    scopes:
      - openid
      - profile
      - email
    audiences:
      - proxy
```

**Key Requirements**:
- Redirect URI MUST use full URL including scheme and host
- For Entra ID, use `http://localhost:8080` (not custom domain)
- Scopes must include at minimum `openid` for OIDC
- PKCE is automatically required (S256)

### 4. TLS/Domain Configuration

**Structure** (refactored from `domain_names` to `tls.domains`):
```yaml
server:
  tls:
    mode: autocert
    domains:
      - localhost
      - demo-xero.dev.nexxia.com.au
      - demo-kb.dev.nexxia.com.au
    cache_dir: ./.certs
    email: admin@example.com
```

**Environment Variable Override**:
```bash
export OIDCD_SERVER_TLS_DOMAINS="localhost,app1.example.com,app2.example.com"
```

---

## Common Issues & Solutions

### Issue 1: Infinite Redirect Loop

**Symptoms**:
- Browser keeps redirecting between gateway and IdP
- Network tab shows repeated `/authorize` requests
- Cookies not being set or recognized

**Root Causes**:
1. **Cookie name mismatch** - Gateway sets `gw_session` but code expects `session`
2. **Cookie domain mismatch** - Cookies set for `demo-salesforce.dev.nexxia.com.au` but redirect goes to `localhost:8080`
3. **State parameter not preserved** - Original URL lost during OAuth flow

**Solutions**:
```go
// server/proxy.go - Ensure consistent cookie name
http.SetCookie(w, &http.Cookie{
    Name:     "gw_session",  // MUST match sessionCookieName in sessions.go
    Value:    newSession.ID,
    Domain:   pm.cookieDomain,
    // ...
})

// Encode original host in state parameter for cross-domain redirects
func (pm *ProxyManager) generateStateParameter(host, path string) string {
    redirectInfo := fmt.Sprintf("%s|%s", host, path)
    encoded := base64.RawURLEncoding.EncodeToString([]byte(redirectInfo))
    return fmt.Sprintf("proxy_auth_%d_%s", time.Now().UnixNano(), encoded)
}
```

### Issue 2: "unknown client" Error

**Symptoms**:
```
authorize invalid request","error":"unknown client"
```

**Solution**:
Add the `gateway-proxy` client to `config.yaml`:
```yaml
clients:
  - client_id: gateway-proxy
    redirect_uris:
      - http://localhost:8080/callback/entra
```

### Issue 3: "invalid redirect_uri" Error

**Symptoms**:
OAuth provider rejects redirect URI during authorization

**Root Cause**:
Redirect URI sent as path-only (e.g., `/callback`) instead of full URL

**Solution**:
Always use full URL with scheme and host:
```go
// WRONG
redirectURI := "/callback/entra"

// CORRECT
redirectURI := "http://localhost:8080/callback/entra"
```

### Issue 4: "pkce required" Error

**Symptoms**:
IdP (especially Entra ID) returns error: "PKCE required"

**Solution**:
Generate PKCE parameters in authorization request:
```go
verifierBytes := make([]byte, 32)
rand.Read(verifierBytes)
verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

sum := sha256.Sum256([]byte(verifier))
challenge := base64.RawURLEncoding.EncodeToString(sum[:])

authURL := fmt.Sprintf("%s?client_id=%s&code_challenge=%s&code_challenge_method=S256&...",
    authorizeURL, clientID, challenge)
```

### Issue 5: Docker Build Fails - "config.example.yaml not found"

**Symptoms**:
```
COPY failed: file not found in build context
```

**Root Cause**:
Dockerfile was copying `config.example.yaml` which doesn't exist

**Solution**:
Update Dockerfile to use `config.yaml`:
```dockerfile
COPY config.yaml /app/config.yaml
```

---

## Testing Workflows

### Workflow 1: Test BFF Pattern

1. **Start services**:
   ```bash
   docker-compose up --build
   ```

2. **Access BFF client**:
   - Open browser: `http://localhost:3001`
   - Click "Login with OIDC"
   - Should redirect to Entra ID login
   - After login, redirected back with user info displayed

3. **Verify tokens**:
   - Check browser console for ID token claims
   - Verify `email`, `name`, `preferred_username` fields
   - Access token should be kept server-side (not in browser)

### Workflow 2: Test Reverse Proxy Pattern

1. **Update hosts file** (see section 2 above)

2. **Start services**:
   ```bash
   docker-compose up --build
   ```

3. **Test public route** (no auth required):
   ```bash
   curl http://demo-xero.dev.nexxia.com.au:8080/
   # Should return response from backend1
   ```

4. **Test protected route** (requires auth):
   - Open browser: `http://demo-salesforce.dev.nexxia.com.au:8080`
   - Should redirect to Entra ID login
   - After login, redirected back to original URL
   - Response from `proxy-backend` with user context

5. **Verify session sharing**:
   - After authenticating on `demo-salesforce`, access `demo-kb`
   - Should NOT require re-authentication (session cookie shared)

### Workflow 3: Test Microservice Pattern

1. **Get access token** via BFF or direct token endpoint:
   ```bash
   # Using client credentials flow
   curl -X POST http://localhost:8080/token \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -d 'grant_type=client_credentials&client_id=webapp&scope=openid&audience=ai-gateway'
   ```

2. **Call protected microservice**:
   ```bash
   curl http://localhost:8080/protected \
     -H "Authorization: Bearer <access_token>"
   ```

3. **Verify JWT validation**:
   - Valid token → 200 OK with response
   - Invalid/expired token → 401 Unauthorized
   - Valid token but wrong audience → 403 Forbidden

---

## Configuration Validation Checklist

When modifying configuration, verify:

- [ ] `server.public_url` uses `localhost` for Entra ID compatibility
- [ ] `server.cookie_domain` is empty for localhost, or matches public_url domain for production
- [ ] `server.tls.domains` includes all proxy route hostnames
- [ ] `clients[].redirect_uris` uses full URLs with scheme and host
- [ ] `clients[].redirect_uris` for Entra must use `localhost` or HTTPS
- [ ] `gateway-proxy` client exists with correct redirect URIs
- [ ] `proxy.routes[].host` matches TLS domains
- [ ] `proxy.routes[].target` points to correct backend service name
- [ ] Environment variables use correct prefixes (e.g., `OIDCD_SERVER_TLS_DOMAINS`)

---

## Key Code Locations

### Session Management
- **`server/sessions.go`**: SessionManager with cookie domain support
  - Key constant: `sessionCookieName = "gw_session"`
  - Cookie domain set from `cfg.Server.CookieDomain`

### Proxy Authentication
- **`server/proxy.go`**: ProxyManager handling routes and authentication
  - State parameter encoding/decoding for cross-domain redirects
  - OAuth callback handler creating sessions
  - Session validation middleware

### Configuration
- **`server/config.go`**: Config structs and validation
  - TLS configuration under `ServerConfig.TLS`
  - Cookie domain validation against public_url
  - Environment variable mapping

### Main Application
- **`main.go`**: Application bootstrap
  - TLS autocert setup using `cfg.Server.TLS.Domains`
  - Proxy manager initialization

---

## Advanced Scenarios

### Scenario: Production with Subdomain Cookie Sharing

**Requirement**: Multiple apps on subdomains share authentication

**Configuration**:
```yaml
server:
  public_url: https://auth.example.com
  cookie_domain: .example.com  # Leading dot for subdomain sharing
  tls:
    mode: autocert
    domains:
      - auth.example.com
      - app1.example.com
      - app2.example.com
      - app3.example.com

clients:
  - client_id: gateway-proxy
    redirect_uris:
      - https://auth.example.com/callback/entra

proxy:
  routes:
    - host: app1.example.com
      target: http://backend1:3000
      require_auth: true
    - host: app2.example.com
      target: http://backend2:3000
      require_auth: true
```

**Flow**:
1. User accesses `https://app1.example.com`
2. No session → redirect to `https://auth.example.com/authorize`
3. After Entra auth → cookie set for `.example.com`
4. User accesses `https://app2.example.com` → session cookie valid, no re-auth needed

### Scenario: Injecting User Context to Legacy Apps

**Requirement**: Legacy application needs user email/name but can't handle OAuth

**Configuration**:
```yaml
proxy:
  routes:
    - host: legacy-app.example.com
      target: http://legacy-backend:8080
      require_auth: true
      inject_jwt: true
      jwt_header_name: X-Auth-Token
      inject_as_bearer: true
      inject_user_claims: true
      claims_headers:
        email: X-User-Email
        name: X-User-Name
        sub: X-User-ID
```

**Backend receives**:
```
GET /dashboard HTTP/1.1
Host: legacy-app.example.com
Authorization: Bearer eyJhbGc...
X-User-Email: user@example.com
X-User-Name: John Doe
X-User-ID: entra|abc123
```

**Legacy app can**:
- Read `X-User-Email` header for user context
- Optionally validate `Authorization` JWT for defense-in-depth
- Implement authorization logic based on user claims

---

## Debugging Tips for AI Agents

### 1. Check Docker Logs
```bash
# Gateway logs
docker logs oidcd-gateway

# BFF client logs
docker logs oidc-client

# Backend logs
docker logs backend1
docker logs proxy-backend
```

### 2. Verify Network Connectivity
```bash
# From inside oidcd container
docker exec -it oidcd-gateway wget -O- http://backend1:3000/

# Check DNS resolution
docker exec -it oidcd-gateway nslookup backend1
```

### 3. Inspect Configuration
```bash
# View loaded config
docker exec -it oidcd-gateway cat /app/config.yaml

# Check environment variables
docker exec -it oidcd-gateway env | grep OIDCD_
```

### 4. Test Endpoints
```bash
# OIDC discovery
curl http://localhost:8080/.well-known/openid-configuration

# JWKS
curl http://localhost:8080/.well-known/jwks.json

# Health check
curl http://localhost:8080/.well-known/openid-configuration
```

### 5. Browser DevTools
- **Network tab**: Track redirect chains, check for loops
- **Application tab**: Inspect cookies (name, domain, path, expiry)
- **Console tab**: Look for JavaScript errors in BFF client

---

## Summary for AI Agents

**When working with this repository**:

1. ✅ **Always use `config.yaml`** (not `config.example.yaml`)
2. ✅ **Use `localhost` for Entra ID** redirect URIs in development
3. ✅ **Set `cookie_domain: ""`** for localhost testing
4. ✅ **Use full URLs** in redirect_uris (scheme + host + path)
5. ✅ **Configure `gateway-proxy` client** for reverse proxy pattern
6. ✅ **Match proxy route hosts** with TLS domains
7. ✅ **Update hosts file** for custom domain testing
8. ✅ **Use `server.tls.domains`** (not `server.domain_names`)
9. ✅ **Set consistent cookie names** (`gw_session`)
10. ✅ **Encode state parameter** for cross-domain proxy redirects

**Common pitfalls to avoid**:

1. ❌ Using custom domains with Entra ID over HTTP
2. ❌ Mismatched cookie names between proxy and session manager
3. ❌ Path-only redirect URIs instead of full URLs
4. ❌ Missing PKCE parameters in OAuth flow
5. ❌ Cookie domain mismatch with public_url
6. ❌ Forgetting to add `gateway-proxy` client
7. ❌ Not encoding original URL in OAuth state for proxied requests

**Testing verification**:

- ✅ BFF pattern: `http://localhost:3001` → successful login → user info displayed
- ✅ Proxy public: `curl http://demo-xero.dev.nexxia.com.au:8080` → 200 OK
- ✅ Proxy protected: Browser to `http://demo-salesforce.dev.nexxia.com.au:8080` → login → access granted
- ✅ Session sharing: Auth on one domain → access another domain without re-auth
- ✅ Microservice: Bearer token → backend validates JWT → 200 OK or 401/403

---

*This guide is based on actual implementation lessons learned during the development and debugging of the reverse proxy authentication pattern.*
