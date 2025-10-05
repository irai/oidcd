# OIDC Gateway - AI Integration Guide

**Purpose:** This document helps AI assistants understand how to integrate applications with the OIDC gateway for authentication and authorization.

---

## Quick Overview

This is an **OIDC/OAuth2 Authorization Server** that:
- Acts as a centralized authentication gateway
- Delegates login to Microsoft Entra ID (Azure AD) or Auth0
- Issues JWT access tokens for API authorization
- Provides reverse proxy with host-based routing
- Terminates TLS at the edge

**Use this when:** You need to add authentication to a web application or API.

---

## Integration Patterns

### Pattern 1: Frontend Application (BFF - Backend For Frontend)

**When to use:** Web applications that need user login

**Architecture:**
```
Browser → Your BFF App → OIDC Gateway → Microsoft 365
              ↓
         HTTP-only cookie
         (stores tokens server-side)
```

**Implementation Steps:**

1. **Register your application in config.yaml:**
```yaml
oauth2_clients:
  - client_id: "your-app"
    client_secret: ""  # Leave empty for public clients
    redirect_uris:
      - http://localhost:3000/callback
    scopes:
      - openid
      - profile
      - email
    audiences:
      - oidcd
```

2. **Add these dependencies to your app:**
```go
// Go
import "github.com/coreos/go-oidc/v3/oidc"
import "golang.org/x/oauth2"

// Or for Node.js
npm install openid-client

// Or for Python
pip install authlib
```

3. **Implement OAuth2 Authorization Code Flow with PKCE:**

```go
// Example Go code
package main

import (
    "github.com/coreos/go-oidc/v3/oidc"
    "golang.org/x/oauth2"
)

func main() {
    ctx := context.Background()

    // Discover OIDC configuration
    provider, _ := oidc.NewProvider(ctx, "http://localhost:8080")

    // Configure OAuth2
    oauth2Config := oauth2.Config{
        ClientID:     "your-app",
        RedirectURL:  "http://localhost:3000/callback",
        Endpoint:     provider.Endpoint(),
        Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
    }

    // Step 1: Redirect to /authorize
    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        state := generateRandomState()
        verifier := oauth2.GenerateVerifier()

        // Store state and verifier in session
        session.Set("state", state)
        session.Set("verifier", verifier)

        url := oauth2Config.AuthCodeURL(
            state,
            oauth2.S256ChallengeOption(verifier),
        )
        http.Redirect(w, r, url, http.StatusFound)
    })

    // Step 2: Handle callback
    http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
        state := session.Get("state")
        verifier := session.Get("verifier")

        if r.URL.Query().Get("state") != state {
            http.Error(w, "Invalid state", http.StatusBadRequest)
            return
        }

        // Exchange code for tokens
        token, _ := oauth2Config.Exchange(
            ctx,
            r.URL.Query().Get("code"),
            oauth2.VerifierOption(verifier),
        )

        // Store tokens in session (server-side)
        session.Set("access_token", token.AccessToken)
        session.Set("refresh_token", token.RefreshToken)

        http.Redirect(w, r, "/dashboard", http.StatusFound)
    })
}
```

4. **Call APIs with the access token:**
```go
// Add Bearer token to requests
client := &http.Client{}
req, _ := http.NewRequest("GET", "http://localhost:8080/api/data", nil)
req.Header.Set("Authorization", "Bearer "+accessToken)
resp, _ := client.Do(req)
```

---

### Pattern 2: Microservice / API (Token Validation)

**When to use:** Backend services that need to validate JWT tokens

**Architecture:**
```
API Request with Bearer token
    ↓
Your Microservice (validates JWT)
    ↓
OIDC Gateway JWKS endpoint
```

**Implementation Steps:**

1. **Add the validation SDK to your Dockerfile:**
```dockerfile
FROM golang:1.25-alpine AS build
WORKDIR /src

# Copy the OIDC client SDK
COPY --from=oidcd/client /go/pkg/mod/oidcd/client ./client

# Your app code
COPY . .
RUN go build -o /app/service .

FROM alpine:3.19
COPY --from=build /app/service /usr/local/bin/service
ENTRYPOINT ["/usr/local/bin/service"]
```

2. **Use the client SDK to validate tokens:**
```go
package main

import (
    "net/http"
    "oidcd/client"
)

func main() {
    // Initialize validator
    validator := client.NewValidator(client.ValidatorConfig{
        Issuer:            "http://localhost:8080",
        JWKSURL:           "http://localhost:8080/.well-known/jwks.json",
        ExpectedAudiences: []string{"oidcd"},
    })

    // Protect your endpoints
    http.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
        // Extract token from Authorization header
        token := extractBearerToken(r.Header.Get("Authorization"))

        // Validate token
        claims, err := validator.Validate(r.Context(), token)
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Token is valid - use claims
        userID := claims.Subject
        scopes := claims.Scopes

        // Your business logic here
        w.Write([]byte("Hello " + userID))
    })

    http.ListenAndServe(":3000", nil)
}

func extractBearerToken(header string) string {
    parts := strings.SplitN(header, " ", 2)
    if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
        return parts[1]
    }
    return ""
}
```

3. **Add to docker-compose.yml:**
```yaml
services:
  your-service:
    build: .
    environment:
      - OIDC_ISSUER=http://oidcd-gateway:8080
      - JWKS_URL=http://oidcd-gateway:8080/.well-known/jwks.json
      - AUDIENCE=oidcd
    networks:
      - oidc-net
    depends_on:
      oidcd-gateway:
        condition: service_healthy
```

---

### Pattern 3: Service Behind Reverse Proxy

**When to use:** Services that should be accessed through the gateway

**Architecture:**
```
Browser/Client → OIDC Gateway (proxy) → Your Service
                    ↓
            (validates token if required)
```

**Implementation Steps:**

1. **Add proxy route to config.yaml:**
```yaml
proxy:
  routes:
    # Public service (no auth required)
    - host: myapp.example.com
      target: http://myapp:3000
      require_auth: false
      preserve_host: false

    # Protected service (requires authentication via session cookie)
    - host: api.example.com
      target: http://myapi:3000
      require_auth: true
      preserve_host: false
```

2. **Your service receives pre-authenticated requests:**
```go
// Your service doesn't need to validate authentication
// Gateway already validated the session before proxying
func handler(w http.ResponseWriter, r *http.Request) {
    // Your business logic
    w.Write([]byte("Authenticated request received"))
}
```

3. **Add to docker-compose.yml:**
```yaml
services:
  myapp:
    build: .
    networks:
      - oidc-net  # Same network as gateway
    # No ports exposed - only accessible through gateway
```

---

## Docker Compose Integration

**Complete example for adding your service:**

```yaml
version: '3.8'

networks:
  oidc-net:
    external: true  # Use existing OIDC network

services:
  # Your application
  myapp:
    build: .
    container_name: myapp
    environment:
      # For BFF pattern
      - OIDC_ISSUER=http://oidcd-gateway:8080
      - CLIENT_ID=myapp
      - REDIRECT_URL=http://localhost:3002/callback

      # For microservice pattern
      - JWKS_URL=http://oidcd-gateway:8080/.well-known/jwks.json
      - AUDIENCE=oidcd
    ports:
      - "3002:3000"  # Only if directly accessible
    networks:
      - oidc-net
    depends_on:
      oidcd-gateway:
        condition: service_healthy
```

**Connect to existing OIDC stack:**
```bash
# Start your app connected to OIDC network
docker-compose up -d
```

---

## Token Structure

**ID Token (for user identity):**
```json
{
  "iss": "http://localhost:8080",
  "sub": "user123",
  "aud": "your-app",
  "exp": 1234567890,
  "iat": 1234567800,
  "email": "user@example.com",
  "name": "John Doe",
  "preferred_username": "john",
  "idp": "entra"
}
```

**Access Token (for API authorization):**
```json
{
  "iss": "http://localhost:8080",
  "sub": "user123",
  "aud": "oidcd",
  "exp": 1234567890,
  "iat": 1234567800,
  "jti": "token-id",
  "scope": "openid profile email",
  "client_id": "your-app",
  "idp": "entra"
}
```

---

## Environment Variables

**Required for your application:**

| Variable | Description | Example |
|----------|-------------|---------|
| `OIDC_ISSUER` | Gateway URL | `http://localhost:8080` |
| `CLIENT_ID` | Your app's client ID | `myapp` |
| `CLIENT_SECRET` | Client secret (confidential clients only) | `secret123` |
| `REDIRECT_URL` | OAuth callback URL | `http://localhost:3000/callback` |
| `JWKS_URL` | JWKS endpoint for validation | `http://localhost:8080/.well-known/jwks.json` |
| `AUDIENCE` | Expected token audience | `oidcd` |

---

## Common Endpoints

**OIDC Discovery:**
```
GET http://localhost:8080/.well-known/openid-configuration
```

**Authorization (start login flow):**
```
GET http://localhost:8080/authorize?
  response_type=code&
  client_id=your-app&
  redirect_uri=http://localhost:3000/callback&
  scope=openid profile email&
  state=random-state&
  code_challenge=base64url-sha256&
  code_challenge_method=S256
```

**Token Exchange:**
```
POST http://localhost:8080/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE&
redirect_uri=http://localhost:3000/callback&
client_id=your-app&
code_verifier=VERIFIER
```

**JWKS (for validation):**
```
GET http://localhost:8080/.well-known/jwks.json
```

**User Info:**
```
GET http://localhost:8080/userinfo
Authorization: Bearer ACCESS_TOKEN
```

---

## Example: Complete Dockerfile for Your Service

```dockerfile
# Multi-stage build
FROM golang:1.25-alpine AS build
WORKDIR /src

# Copy OIDC client SDK (for token validation)
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /app/service .

# Runtime
FROM alpine:3.19
RUN addgroup -S app && adduser -S app -G app

COPY --from=build /app/service /usr/local/bin/service

USER app
EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/service"]
```

---

## Security Best Practices

1. **Always use PKCE** for public clients (SPAs, mobile apps)
2. **Store tokens server-side** in BFF pattern (not in browser)
3. **Use HTTPS in production** (gateway handles TLS termination)
4. **Validate tokens on every request** in microservices
5. **Check required scopes** for fine-grained authorization
6. **Use short-lived access tokens** (5-10 minutes)
7. **Implement token refresh** using refresh tokens

---

## Troubleshooting

**Problem:** "Invalid issuer"
- **Solution:** Ensure `OIDC_ISSUER` matches exactly (no trailing slash)

**Problem:** "Redirect URI mismatch"
- **Solution:** Add your redirect URI to `config.yaml` under `clients[].redirect_uris`

**Problem:** "Token validation failed"
- **Solution:** Check that `AUDIENCE` matches your client's configured audiences

**Problem:** "Cannot connect to gateway"
- **Solution:** Ensure your service is on the same Docker network (`oidc-net`)

---

## Testing Your Integration

**1. Test OIDC discovery:**
```bash
curl http://localhost:8080/.well-known/openid-configuration
```

**2. Test token validation:**
```bash
# Get a token from the gateway first
TOKEN="your-access-token"

# Call your API
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:3000/api/protected
```

**3. Test via proxy:**
```bash
curl -H "Host: myapp.example.com" \
     -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/
```

---

## Reference Implementation

See `cmd/client/` and `cmd/backend/` for complete working examples:

- **cmd/client/** - BFF pattern (web app with login)
- **cmd/backend/** - Microservice pattern (JWT validation)

Both are production-ready templates you can copy and modify.
