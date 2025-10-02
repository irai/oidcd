package main

import (
	"encoding/json"
	"fmt"
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
	http.HandleFunc("/health", handleHealth)

	fmt.Printf("Service running at http://localhost:%s\n", port)
	fmt.Println("\nTest with gateway proxy:")
	fmt.Println("curl -H 'Host: api.example.local' http://localhost:8080/api/protected")
	fmt.Println("curl -H 'Host: api.example.local' http://localhost:8080/api/public")

	log.Fatal(http.ListenAndServe(":"+port, nil))
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

