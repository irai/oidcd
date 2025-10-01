package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"oidcd/client"
)

type App struct {
	serviceName string
	validator   *client.Validator
	logger      *slog.Logger
}

func main() {
	serviceName := getEnv("SERVICE_NAME", "Backend Service")
	listenAddr := getEnv("LISTEN_ADDR", "0.0.0.0:3000")
	issuer := getEnv("OIDC_ISSUER", "http://localhost:8080")
	jwksURL := getEnv("JWKS_URL", issuer+"/.well-known/jwks.json")
	audience := getEnv("AUDIENCE", "ai-gateway")

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	validator := client.NewValidator(client.ValidatorConfig{
		Issuer:            issuer,
		JWKSURL:           jwksURL,
		ExpectedAudiences: []string{audience},
	})

	app := &App{
		serviceName: serviceName,
		validator:   validator,
		logger:      logger,
	}

	http.HandleFunc("/", app.handleIndex)
	http.HandleFunc("/api/protected", app.handleProtected)
	http.HandleFunc("/api/public", app.handlePublic)
	http.HandleFunc("/health", app.handleHealth)

	logger.Info("backend service starting",
		"service", serviceName,
		"addr", listenAddr,
		"issuer", issuer,
		"audience", audience,
	)

	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>{{.ServiceName}}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1000px;
            margin: 50px auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        h1 { color: #667eea; margin-top: 0; }
        h2 { color: #555; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
        .info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            border-left: 4px solid #667eea;
        }
        .endpoint {
            background: #e9ecef;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
            margin-left: 10px;
        }
        .badge-public { background: #28a745; color: white; }
        .badge-protected { background: #dc3545; color: white; }
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{.ServiceName}}</h1>

        <div class="info">
            <p><strong>Service Type:</strong> Microservice / BFF (Backend For Frontend)</p>
            <p><strong>Purpose:</strong> Validates JWT tokens from OIDC gateway</p>
            <p><strong>Authentication:</strong> Bearer token required for protected endpoints</p>
        </div>

        <h2>Available Endpoints</h2>

        <div class="endpoint">
            <strong>GET /</strong> <span class="badge badge-public">PUBLIC</span>
            <br>This page - service information
        </div>

        <div class="endpoint">
            <strong>GET /health</strong> <span class="badge badge-public">PUBLIC</span>
            <br>Health check endpoint
        </div>

        <div class="endpoint">
            <strong>GET /api/public</strong> <span class="badge badge-public">PUBLIC</span>
            <br>Public API endpoint (no authentication required)
        </div>

        <div class="endpoint">
            <strong>GET /api/protected</strong> <span class="badge badge-protected">PROTECTED</span>
            <br>Protected API endpoint - requires valid JWT token
            <br><small>Include <code>Authorization: Bearer &lt;token&gt;</code> header</small>
        </div>

        <h2>How to Test</h2>
        <div class="info">
            <p><strong>1. Get a token from the gateway:</strong></p>
            <p>Visit the client app, login, and copy the access token</p>

            <p><strong>2. Call the protected endpoint:</strong></p>
            <code>curl -H "Authorization: Bearer &lt;token&gt;" http://localhost:8080/api/protected</code>

            <p><strong>3. View decoded JWT claims:</strong></p>
            <p>The protected endpoint will validate the token and return the decoded claims</p>
        </div>

        <h2>Token Validation</h2>
        <div class="info">
            <p>This service validates JWT tokens by:</p>
            <ul>
                <li>Verifying the signature using JWKS from the gateway</li>
                <li>Checking the issuer matches the expected issuer</li>
                <li>Validating the audience claim</li>
                <li>Ensuring the token hasn't expired</li>
                <li>Optionally checking required scopes</li>
            </ul>
        </div>
    </div>
</body>
</html>`

	t := template.Must(template.New("index").Parse(tmpl))
	data := struct {
		ServiceName string
	}{
		ServiceName: a.serviceName,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		a.logger.Error("template error", "error", err)
	}
}

func (a *App) handlePublic(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"service": a.serviceName,
		"message": "This is a public endpoint - no authentication required",
		"path":    r.URL.Path,
		"method":  r.Method,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (a *App) handleProtected(w http.ResponseWriter, r *http.Request) {
	// Extract token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, `{"error":"missing_token","message":"Authorization header required"}`, http.StatusUnauthorized)
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		http.Error(w, `{"error":"invalid_token","message":"Invalid authorization header format"}`, http.StatusUnauthorized)
		return
	}

	token := parts[1]

	// Validate token
	claims, err := a.validator.Validate(r.Context(), token)
	if err != nil {
		a.logger.Error("token validation failed", "error", err)
		http.Error(w, fmt.Sprintf(`{"error":"invalid_token","message":"%s"}`, err.Error()), http.StatusUnauthorized)
		return
	}

	// Token is valid - return the claims
	response := map[string]interface{}{
		"service":       a.serviceName,
		"message":       "Token validated successfully",
		"authenticated": true,
		"claims": map[string]interface{}{
			"sub":       claims.Subject,
			"iss":       claims.Issuer,
			"aud":       claims.Audiences,
			"exp":       claims.ExpiresAt.Unix(),
			"iat":       claims.IssuedAt.Unix(),
			"scopes":    claims.Scopes,
			"client_id": claims.ClientID,
			"jti":       claims.TokenID,
			"raw":       claims.Raw,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": a.serviceName,
	})
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
