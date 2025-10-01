# Running OIDC Gateway with Test Client

This guide explains how to run the OIDC gateway and test client application using Docker Compose.

## Prerequisites

1. Docker and Docker Compose installed
2. A valid `config.yaml` file with Microsoft Entra ID credentials configured

## Configuration

Before running, ensure your `config.yaml` has the correct settings:

```yaml
providers:
  default: "entra"
  entra:
    issuer: "https://login.microsoftonline.com/common/v2.0"
    tenant_id: "YOUR_TENANT_ID"
    client_id: "YOUR_ENTRA_APP_CLIENT_ID"
    client_secret: "YOUR_ENTRA_APP_CLIENT_SECRET"

clients:
  - client_id: "webapp"
    client_secret: ""
    redirect_uris:
      - "http://localhost:3000/callback"
    scopes: ["openid", "profile", "email"]
    audiences: ["ai-gateway"]
```

### Microsoft Entra ID App Registration

In your Azure portal, configure the redirect URI for your app registration:
- Add `http://localhost:8080/callback/entra` for the gateway callback

## Running the Services

Start both services with:

```bash
docker-compose up --build
```

This will:
1. Build and start the OIDC gateway on `http://localhost:8080`
2. Build and start the test client on `http://localhost:3000`

## Testing the OIDC Flow

1. Open your browser to `http://localhost:3000`
2. Click "Login with OIDC"
3. You'll be redirected to the gateway, then to Microsoft 365 for authentication
4. After authenticating with your Microsoft 365 account, you'll be redirected back to the client
5. The client will display your username extracted from the JWT token

## Viewing the Profile

Click "View Full Profile" to see:
- All JWT claims from the ID token
- The access token issued by the gateway

## Architecture

```
Browser <-> Client App (port 3000) <-> OIDC Gateway (port 8080) <-> Microsoft Entra ID
```

The client app:
- Implements the OAuth 2.0 Authorization Code flow with PKCE
- Validates JWT tokens received from the gateway
- Displays user information from the token claims

## Stopping the Services

```bash
docker-compose down
```

## Logs

View logs from both services:

```bash
docker-compose logs -f
```

View logs from a specific service:

```bash
docker-compose logs -f oidcd
docker-compose logs -f client
```
