package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

func main() {
	port := "3002"
	fmt.Printf("Enhanced Proxy Backend Service starting on port %s\n", port)
	fmt.Println("This service expects JWT injection from the OIDC gateway proxy")

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/api/protected", handleProtectedAPI)
	http.HandleFunc("/api/public", handlePublicAPI)
	http.HandleFunc("/page/protected", handleProtectedPage)
	http.HandleFunc("/health", handleHealth)

	fmt.Printf("Service running at http://localhost:%s\n", port)
	fmt.Println("\nTest with gateway proxy:")
	fmt.Println("curl -H 'Host: api.example.local' http://localhost:8080/api/protected")
	fmt.Println("curl -H 'Host: api.example.local' http://localhost:8080/api/public")

	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// decodeJWT decodes a JWT token and returns the payload as a formatted JSON string
func decodeJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Try standard base64 if URL encoding fails
		payload, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return "", fmt.Errorf("failed to decode JWT payload: %w", err)
		}
	}

	// Pretty print the JSON
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	prettyJSON, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to format JWT claims: %w", err)
	}

	return string(prettyJSON), nil
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>Enhanced Proxy Backend Service</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; }
        .endpoint { background: #f5f5f5; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .header { color: #666; font-family: monospace; }
    </style>
</head>
<body>
    <h1>Enhanced Proxy Backend Service</h1>
    <p>This service demonstrates automatic JWT injection from the OIDC gateway proxy.</p>
    
    <div class="endpoint">
        <h3>Protected Endpoint</h3>
        <a href="/api/protected">GET /api/protected</a>
        <p>Requires authentication via gateway proxy. Gateway injects:</p>
        <ul>
            <li><code class="header">X-User-ID</code>: Authenticated user ID</li>
            <li><code class="header">X-User-Email</code>: User email from IdP</li>
            <li><code class="header">X-Auth-Token</code>: Gateway-issued JWT</li>
            <li><code class="header">X-Auth-Type</code>: Authentication method (bearer/cookie)</li>
        </ul>
    </div>

    <div class="endpoint">
        <h3>Public Endpoint</h3>
        <a href="/api/public">GET /api/public</a>
        <p>No authentication required.</p>
    </div>

    <div class="endpoint">
        <h3>Protected Page</h3>
        <a href="/page/protected">GET /page/protected</a>
        <p>Protected page showing credential information and full HTTP request details.</p>
    </div>

    <div class="endpoint">
        <h3>Health Check</h3>
        <a href="/health">GET /health</a>
        <p>Automatically excluded from authentication by gateway.</p>
    </div>
</body>
</html>`)
}

func handleProtectedAPI(w http.ResponseWriter, r *http.Request) {
	// Extract injected headers from gateway
	userID := r.Header.Get("X-User-ID")
	userEmail := r.Header.Get("X-User-Email")
	userName := r.Header.Get("X-User-Name")
	authType := r.Header.Get("X-Auth-Type")
	authToken := r.Header.Get("X-Auth-Token")
	userScopes := r.Header.Get("X-User-Scopes")

	// Check if client wants JSON response
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		// Show all injected headers for demonstration
		allHeaders := make(map[string]string)
		for name, values := range r.Header {
			if strings.HasPrefix(name, "X-") {
				allHeaders[name] = strings.Join(values, ", ")
			}
		}

		response := map[string]interface{}{
			"service": "Enhanced Proxy Backend",
			"message": "This endpoint is protected by gateway proxy authentication",
			"authentication": map[string]interface{}{
				"user_id":    userID,
				"user_email": userEmail,
				"user_name":  userName,
				"auth_type":  authType,
				"scopes":     userScopes,
				"has_token":  authToken != "",
			},
			"injected_headers": allHeaders,
			"forwarded_info": map[string]interface{}{
				"method":     r.Method,
				"path":       r.URL.Path,
				"user_agent": r.Header.Get("User-Agent"),
				"remote_ip":  r.Header.Get("X-Forwarded-For"),
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// HTML response for browser
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Protected API Response</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 900px; margin: 20px auto; background: #f5f5f5; }
        .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #2196F3; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 25px; border-bottom: 2px solid #ddd; padding-bottom: 8px; }
        .credential { background: #e3f2fd; padding: 12px 15px; margin: 8px 0; border-radius: 5px; border-left: 4px solid #2196F3; }
        .credential strong { color: #1565c0; display: inline-block; min-width: 120px; }
        .credential-value { color: #333; font-family: monospace; }
        .success-badge { background: #4CAF50; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; }
        .info-text { color: #666; margin: 15px 0; }
        .header-list { background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .header-item { padding: 8px; border-bottom: 1px solid #eee; font-family: monospace; font-size: 14px; }
        .header-item:last-child { border-bottom: none; }
        .header-name { color: #1976d2; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Protected API Endpoint <span class="success-badge">AUTHENTICATED</span></h1>
        <p class="info-text">This endpoint is protected by gateway proxy authentication. The credentials below were automatically injected by the OIDC gateway.</p>

        <h2>User Credentials</h2>
`)

	if userID == "" && userEmail == "" && userName == "" {
		fmt.Fprintf(w, `        <p style="color: #f44336;">No user credentials found. Authentication may have failed.</p>`)
	} else {
		fmt.Fprintf(w, `
        <div class="credential">
            <strong>User ID:</strong> <span class="credential-value">%s</span>
        </div>
        <div class="credential">
            <strong>User Email:</strong> <span class="credential-value">%s</span>
        </div>
        <div class="credential">
            <strong>User Name:</strong> <span class="credential-value">%s</span>
        </div>
        <div class="credential">
            <strong>Auth Type:</strong> <span class="credential-value">%s</span>
        </div>
        <div class="credential">
            <strong>Scopes:</strong> <span class="credential-value">%s</span>
        </div>
        <div class="credential">
            <strong>Auth Token:</strong> <span class="credential-value">%s</span>
        </div>
`, userID, userEmail, userName, authType, userScopes,
			func() string {
				if authToken != "" {
					if len(authToken) > 60 {
						return authToken[:60] + "..."
					}
					return authToken
				}
				return "(none)"
			}())

		// Decode and display JWT content if available
		if authToken != "" {
			if jwtContent, err := decodeJWT(authToken); err == nil {
				fmt.Fprintf(w, `
        <h2>JWT Token Content</h2>
        <div class="header-list">
            <pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word;">%s</pre>
        </div>
`, jwtContent)
			}
		}
	}

	// Show all X- headers
	fmt.Fprintf(w, `
        <h2>Injected Headers</h2>
        <div class="header-list">
`)

	hasHeaders := false
	for name, values := range r.Header {
		if strings.HasPrefix(name, "X-") {
			hasHeaders = true
			fmt.Fprintf(w, `            <div class="header-item"><span class="header-name">%s:</span> %s</div>
`, name, strings.Join(values, ", "))
		}
	}

	if !hasHeaders {
		fmt.Fprintf(w, `            <div class="header-item">No injected headers found</div>`)
	}

	fmt.Fprintf(w, `
        </div>

        <h2>Request Information</h2>
        <div class="credential">
            <strong>Method:</strong> <span class="credential-value">%s</span>
        </div>
        <div class="credential">
            <strong>Path:</strong> <span class="credential-value">%s</span>
        </div>
        <div class="credential">
            <strong>User Agent:</strong> <span class="credential-value">%s</span>
        </div>
        <div class="credential">
            <strong>Remote IP:</strong> <span class="credential-value">%s</span>
        </div>

        <p class="info-text" style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
            <strong>API Usage:</strong> Add <code>Accept: application/json</code> header to get JSON response instead of HTML.
        </p>
    </div>
</body>
</html>`, r.Method, r.URL.Path, r.Header.Get("User-Agent"), r.Header.Get("X-Forwarded-For"))
}

func handlePublicAPI(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"service":   "Enhanced Proxy Backend",
		"message":   "Public endpoint - no authentication required",
		"timestamp": fmt.Sprintf("Request at %v", r.Header.Get("X-Request-Time")),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleProtectedPage(w http.ResponseWriter, r *http.Request) {
	// Extract injected credentials from gateway
	userID := r.Header.Get("X-User-ID")
	userEmail := r.Header.Get("X-User-Email")
	userName := r.Header.Get("X-User-Name")
	authType := r.Header.Get("X-Auth-Type")
	authToken := r.Header.Get("X-Auth-Token")
	userScopes := r.Header.Get("X-User-Scopes")

	// Read request body
	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Request Debug - Protected Page</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1000px; margin: 20px auto; background: #f5f5f5; }
        .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; border-bottom: 2px solid #ddd; padding-bottom: 8px; }
        .section { margin: 20px 0; }
        .credential { background: #e8f5e9; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #4CAF50; }
        .credential strong { color: #2e7d32; display: inline-block; min-width: 120px; }
        .header-table { width: 100%%; border-collapse: collapse; margin: 10px 0; }
        .header-table th, .header-table td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        .header-table th { background: #f0f0f0; font-weight: bold; }
        .header-table tr:hover { background: #f9f9f9; }
        .header-name { font-family: monospace; color: #1976d2; }
        .header-value { font-family: monospace; color: #555; word-break: break-all; }
        .request-line { background: #fff3e0; padding: 15px; margin: 10px 0; border-radius: 5px; font-family: monospace; border-left: 4px solid #ff9800; }
        .body-content { background: #f5f5f5; padding: 15px; margin: 10px 0; border-radius: 5px; font-family: monospace; white-space: pre-wrap; word-wrap: break-word; }
        .alert { background: #fff3cd; border: 1px solid #ffc107; padding: 10px; border-radius: 4px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Protected Page - Full Request Details</h1>
        <p>This page displays credential information injected by the OIDC gateway and the full HTTP request details.</p>

        <h2>Credential Information</h2>
        <div class="section">
`)

	if userID == "" && userEmail == "" && userName == "" {
		fmt.Fprintf(w, `            <div class="alert">WARNING: No credential headers detected. This request may not have been authenticated by the gateway.</div>`)
	} else {
		fmt.Fprintf(w, `
            <div class="credential">
                <strong>User ID:</strong> %s
            </div>
            <div class="credential">
                <strong>User Email:</strong> %s
            </div>
            <div class="credential">
                <strong>User Name:</strong> %s
            </div>
            <div class="credential">
                <strong>Auth Type:</strong> %s
            </div>
            <div class="credential">
                <strong>User Scopes:</strong> %s
            </div>
            <div class="credential">
                <strong>Auth Token:</strong> %s
            </div>
`, userID, userEmail, userName, authType, userScopes,
			func() string {
				if authToken != "" {
					if len(authToken) > 50 {
						return authToken[:50] + "... (truncated)"
					}
					return authToken
				}
				return "(none)"
			}())

		// Decode and display JWT content if available
		if authToken != "" {
			if jwtContent, err := decodeJWT(authToken); err == nil {
				fmt.Fprintf(w, `
        </div>

        <h2>JWT Token Content</h2>
        <div class="section">
            <div class="body-content">%s</div>
        </div>
        <div class="section">
`, jwtContent)
			}
		}
	}

	fmt.Fprintf(w, `
        </div>

        <h2>HTTP Request Line</h2>
        <div class="request-line">
            %s %s %s<br>
            Host: %s
        </div>

        <h2>All HTTP Headers</h2>
        <table class="header-table">
            <thead>
                <tr>
                    <th>Header Name</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
`, r.Method, r.URL.RequestURI(), r.Proto, r.Host)

	for name, values := range r.Header {
		for _, value := range values {
			fmt.Fprintf(w, `                <tr>
                    <td class="header-name">%s</td>
                    <td class="header-value">%s</td>
                </tr>
`, name, value)
		}
	}

	fmt.Fprintf(w, `
            </tbody>
        </table>

        <h2>Request Details</h2>
        <div class="section">
            <div class="credential">
                <strong>Method:</strong> %s
            </div>
            <div class="credential">
                <strong>URL Path:</strong> %s
            </div>
            <div class="credential">
                <strong>Query String:</strong> %s
            </div>
            <div class="credential">
                <strong>Protocol:</strong> %s
            </div>
            <div class="credential">
                <strong>Remote Addr:</strong> %s
            </div>
            <div class="credential">
                <strong>Content Length:</strong> %d bytes
            </div>
        </div>
`, r.Method, r.URL.Path,
	func() string {
		if r.URL.RawQuery != "" {
			return r.URL.RawQuery
		}
		return "(none)"
	}(),
	r.Proto, r.RemoteAddr, r.ContentLength)

	if len(body) > 0 {
		fmt.Fprintf(w, `
        <h2>Request Body</h2>
        <div class="body-content">%s</div>
`, string(body))
	} else {
		fmt.Fprintf(w, `
        <h2>Request Body</h2>
        <div class="body-content">(empty)</div>
`)
	}

	fmt.Fprintf(w, `
    </div>
</body>
</html>`)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":  "healthy",
		"service": "Enhanced Proxy Backend",
		"checks": map[string]interface{}{
			"authentication":  "excluded by gateway",
			"proxy_injection": "not applicable",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

