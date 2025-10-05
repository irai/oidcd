package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInferCORSOrigins(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected []string
	}{
		{
			name: "oauth2_clients_only",
			config: Config{
				OAuth2Clients: []ClientConfig{
					{
						RedirectURIs: []string{
							"http://localhost:3000/callback",
							"http://localhost:3001/auth",
						},
					},
					{
						RedirectURIs: []string{
							"https://app.example.com/callback",
						},
					},
				},
			},
			expected: []string{
				"http://localhost:3000",
				"http://localhost:3001",
				"https://app.example.com",
			},
		},
		{
			name: "proxy_routes_only",
			config: Config{
				Proxy: ProxyConfig{
					Routes: []ProxyRoute{
						{Target: "http://backend1:8080"},
						{Target: "http://backend2:9000/api"},
						{Target: "https://external.api.com/v1"},
					},
				},
			},
			expected: []string{
				"http://backend1:8080",
				"http://backend2:9000",
				"https://external.api.com",
			},
		},
		{
			name: "mixed_oauth2_and_proxy",
			config: Config{
				OAuth2Clients: []ClientConfig{
					{
						RedirectURIs: []string{
							"http://localhost:3000/callback",
							"https://app.example.com/auth",
						},
					},
				},
				Proxy: ProxyConfig{
					Routes: []ProxyRoute{
						{Target: "http://backend:8080"},
						{Target: "https://api.example.com/v1"},
					},
				},
			},
			expected: []string{
				"http://localhost:3000",
				"https://app.example.com",
				"http://backend:8080",
				"https://api.example.com",
			},
		},
		{
			name: "deduplication",
			config: Config{
				OAuth2Clients: []ClientConfig{
					{
						RedirectURIs: []string{
							"http://localhost:3000/callback",
							"http://localhost:3000/auth",
						},
					},
				},
				Proxy: ProxyConfig{
					Routes: []ProxyRoute{
						{Target: "http://localhost:3000/api"},
					},
				},
			},
			expected: []string{
				"http://localhost:3000",
			},
		},
		{
			name: "wildcard_redirect_uri",
			config: Config{
				OAuth2Clients: []ClientConfig{
					{
						RedirectURIs: []string{
							"*",
							"http://localhost:3000/callback",
						},
					},
				},
			},
			expected: []string{
				"http://localhost:3000",
			},
		},
		{
			name: "empty_config",
			config: Config{
				OAuth2Clients: []ClientConfig{},
				Proxy:         ProxyConfig{Routes: []ProxyRoute{}},
			},
			expected: []string{},
		},
		{
			name: "ports_preserved",
			config: Config{
				OAuth2Clients: []ClientConfig{
					{
						RedirectURIs: []string{
							"http://localhost:3000/callback",
							"http://localhost:3001/callback",
							"https://app.example.com:8443/auth",
						},
					},
				},
			},
			expected: []string{
				"http://localhost:3000",
				"http://localhost:3001",
				"https://app.example.com:8443",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origins := tt.config.InferCORSOrigins()

			if len(origins) != len(tt.expected) {
				t.Fatalf("expected %d origins, got %d: %v", len(tt.expected), len(origins), origins)
			}

			// Convert to map for order-independent comparison
			got := make(map[string]bool)
			for _, o := range origins {
				got[o] = true
			}

			for _, expected := range tt.expected {
				if !got[expected] {
					t.Errorf("expected origin %q not found in result: %v", expected, origins)
				}
			}
		})
	}
}

func TestExtractOrigin(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "http_with_path",
			url:      "http://localhost:3000/callback",
			expected: "http://localhost:3000",
		},
		{
			name:     "https_with_port",
			url:      "https://example.com:8443/api/v1",
			expected: "https://example.com:8443",
		},
		{
			name:     "http_no_path",
			url:      "http://backend:8080",
			expected: "http://backend:8080",
		},
		{
			name:     "wildcard",
			url:      "*",
			expected: "",
		},
		{
			name:     "empty",
			url:      "",
			expected: "",
		},
		{
			name:     "no_scheme",
			url:      "localhost:3000/callback",
			expected: "",
		},
		{
			name:     "ipv4_address",
			url:      "http://127.0.0.1:3000/callback",
			expected: "http://127.0.0.1:3000",
		},
		{
			name:     "default_http_port",
			url:      "http://example.com:80/path",
			expected: "http://example.com:80",
		},
		{
			name:     "default_https_port",
			url:      "https://example.com:443/path",
			expected: "https://example.com:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origin := extractOrigin(tt.url)
			if origin != tt.expected {
				t.Errorf("extractOrigin(%q) = %q, expected %q", tt.url, origin, tt.expected)
			}
		})
	}
}

func TestCORSMiddleware(t *testing.T) {
	tests := []struct {
		name               string
		allowedOrigins     []string
		requestOrigin      string
		method             string
		expectCORSHeaders  bool
		expectAllowOrigin  string
		expectStatus       int
		expectBodyExecuted bool
	}{
		{
			name:               "allowed_origin_get",
			allowedOrigins:     []string{"http://localhost:3000"},
			requestOrigin:      "http://localhost:3000",
			method:             "GET",
			expectCORSHeaders:  true,
			expectAllowOrigin:  "http://localhost:3000",
			expectStatus:       http.StatusOK,
			expectBodyExecuted: true,
		},
		{
			name:               "allowed_origin_post",
			allowedOrigins:     []string{"http://localhost:3000"},
			requestOrigin:      "http://localhost:3000",
			method:             "POST",
			expectCORSHeaders:  true,
			expectAllowOrigin:  "http://localhost:3000",
			expectStatus:       http.StatusOK,
			expectBodyExecuted: true,
		},
		{
			name:               "allowed_origin_options",
			allowedOrigins:     []string{"http://localhost:3000"},
			requestOrigin:      "http://localhost:3000",
			method:             "OPTIONS",
			expectCORSHeaders:  true,
			expectAllowOrigin:  "http://localhost:3000",
			expectStatus:       http.StatusNoContent,
			expectBodyExecuted: false,
		},
		{
			name:               "disallowed_origin",
			allowedOrigins:     []string{"http://localhost:3000"},
			requestOrigin:      "http://evil.com",
			method:             "GET",
			expectCORSHeaders:  false,
			expectAllowOrigin:  "",
			expectStatus:       http.StatusOK,
			expectBodyExecuted: true,
		},
		{
			name:               "no_origin_header",
			allowedOrigins:     []string{"http://localhost:3000"},
			requestOrigin:      "",
			method:             "GET",
			expectCORSHeaders:  false,
			expectAllowOrigin:  "",
			expectStatus:       http.StatusOK,
			expectBodyExecuted: true,
		},
		{
			name:               "multiple_allowed_origins",
			allowedOrigins:     []string{"http://localhost:3000", "https://app.example.com"},
			requestOrigin:      "https://app.example.com",
			method:             "GET",
			expectCORSHeaders:  true,
			expectAllowOrigin:  "https://app.example.com",
			expectStatus:       http.StatusOK,
			expectBodyExecuted: true,
		},
		{
			name:               "wildcard_allowed",
			allowedOrigins:     []string{"*"},
			requestOrigin:      "http://any-origin.com",
			method:             "GET",
			expectCORSHeaders:  true,
			expectAllowOrigin:  "http://any-origin.com",
			expectStatus:       http.StatusOK,
			expectBodyExecuted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyExecuted := false
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				bodyExecuted = true
				w.WriteHeader(http.StatusOK)
			})

			middleware := CORSMiddleware(tt.allowedOrigins)
			wrappedHandler := middleware(handler)

			req := httptest.NewRequest(tt.method, "/test", nil)
			if tt.requestOrigin != "" {
				req.Header.Set("Origin", tt.requestOrigin)
			}

			rec := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(rec, req)

			// Check status code
			if rec.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d", tt.expectStatus, rec.Code)
			}

			// Check CORS headers
			allowOrigin := rec.Header().Get("Access-Control-Allow-Origin")
			allowMethods := rec.Header().Get("Access-Control-Allow-Methods")
			allowHeaders := rec.Header().Get("Access-Control-Allow-Headers")
			vary := rec.Header().Get("Vary")

			if tt.expectCORSHeaders {
				if allowOrigin != tt.expectAllowOrigin {
					t.Errorf("expected Allow-Origin %q, got %q", tt.expectAllowOrigin, allowOrigin)
				}
				if allowMethods == "" {
					t.Error("expected Allow-Methods header to be set")
				}
				if allowHeaders == "" {
					t.Error("expected Allow-Headers header to be set")
				}
				if vary != "Origin" {
					t.Errorf("expected Vary: Origin, got %q", vary)
				}
			} else {
				if allowOrigin != "" {
					t.Errorf("expected no Allow-Origin header, got %q", allowOrigin)
				}
			}

			// Check if body was executed
			if bodyExecuted != tt.expectBodyExecuted {
				t.Errorf("expected bodyExecuted=%v, got %v", tt.expectBodyExecuted, bodyExecuted)
			}
		})
	}
}

func TestCORSDefaultHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := CORSMiddleware([]string{"http://localhost:3000"})
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")

	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	allowMethods := rec.Header().Get("Access-Control-Allow-Methods")
	allowHeaders := rec.Header().Get("Access-Control-Allow-Headers")

	// Verify default allowed methods
	expectedMethods := "GET, POST, OPTIONS"
	if allowMethods != expectedMethods {
		t.Errorf("expected Allow-Methods %q, got %q", expectedMethods, allowMethods)
	}

	// Verify default allowed headers
	expectedHeaders := "Authorization, Content-Type"
	if allowHeaders != expectedHeaders {
		t.Errorf("expected Allow-Headers %q, got %q", expectedHeaders, allowHeaders)
	}
}
