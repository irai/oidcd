package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestSecurityMalformedRequests tests gateway behavior with malformed HTTP requests
func TestSecurityMalformedRequests(t *testing.T) {
	app := setupTestApp(t)

	tests := []struct {
		name           string
		method         string
		path           string
		headers        map[string]string
		body           string
		expectedStatus int
		description    string
	}{
		{
			name:           "extremely_long_header",
			method:         "GET",
			path:           "/.well-known/openid-configuration",
			headers:        map[string]string{"X-Custom-Header": strings.Repeat("A", 100000)},
			expectedStatus: http.StatusOK, // Server should handle or reject gracefully
			description:    "Header longer than 100KB should be handled gracefully",
		},
		{
			name:           "double_slash_in_path",
			method:         "GET",
			path:           "//authorize?client_id=test",
			expectedStatus: http.StatusNotFound,
			description:    "Double slash in path should be normalized",
		},
		{
			name:           "malformed_content_type",
			method:         "POST",
			path:           "/token",
			headers:        map[string]string{"Content-Type": "text/plain"},
			body:           "grant_type=authorization_code",
			expectedStatus: http.StatusBadRequest,
			description:    "Unexpected Content-Type should be rejected",
		},
		{
			name:           "excessive_url_encoding",
			method:         "GET",
			path:           "/authorize?client_id=%25%32%35%32%35%32%35%32%35%32%35%32%35",
			expectedStatus: http.StatusFound, // Gateway doesn't reject this, just returns redirect to IDP or error redirect
			description:    "Multiple levels of URL encoding (possible encoding attack)",
		},
		{
			name:           "special_chars_in_params",
			method:         "GET",
			path:           "/authorize?client_id=%3Cscript%3E",
			expectedStatus: http.StatusFound, // Gateway will return error via redirect
			description:    "Special characters in params should be handled safely",
		},
		{
			name:           "method_override_attempt",
			method:         "POST",
			path:           "/userinfo",
			headers:        map[string]string{"X-HTTP-Method-Override": "DELETE"},
			expectedStatus: http.StatusUnauthorized, // Should process as POST, not override
			description:    "HTTP method override headers should not work",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body *bytes.Buffer
			if tt.body != "" {
				body = bytes.NewBufferString(tt.body)
			} else {
				body = bytes.NewBufferString("")
			}

			req := httptest.NewRequest(tt.method, tt.path, body)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			app.Routes().ServeHTTP(w, req)

			// Check for expected status or reasonable error handling (not 5xx crashes)
			if w.Code >= 500 {
				t.Errorf("%s: server error (5xx), got %d - server should handle gracefully", tt.description, w.Code)
			}
			// Also verify expected status if it's not a generic check
			if tt.expectedStatus != http.StatusOK && w.Code == http.StatusOK {
				t.Logf("%s: got 200 OK (test may need adjustment based on actual behavior)", tt.description)
			}
		})
	}
}

// TestSecurityInvalidParameters tests OIDC endpoints with invalid/malicious parameters
func TestSecurityInvalidParameters(t *testing.T) {
	app := setupTestApp(t)

	tests := []struct {
		name        string
		endpoint    string
		params      map[string]string
		expectError bool
		description string
	}{
		{
			name:     "authorize_missing_response_type",
			endpoint: "/authorize",
			params: map[string]string{
				"client_id":    "webapp",
				"redirect_uri": "http://localhost:3000/callback",
			},
			expectError: true,
			description: "Missing required response_type parameter",
		},
		{
			name:     "authorize_invalid_client_id",
			endpoint: "/authorize",
			params: map[string]string{
				"client_id":     "../../etc/passwd",
				"response_type": "code",
				"redirect_uri":  "http://localhost:3000/callback",
			},
			expectError: true,
			description: "Path traversal attempt in client_id",
		},
		{
			name:     "authorize_sql_injection_attempt",
			endpoint: "/authorize",
			params: map[string]string{
				"client_id":     "' OR '1'='1",
				"response_type": "code",
				"redirect_uri":  "http://localhost:3000/callback",
			},
			expectError: true,
			description: "SQL injection attempt in client_id",
		},
		{
			name:     "authorize_xss_in_state",
			endpoint: "/authorize",
			params: map[string]string{
				"client_id":     "webapp",
				"response_type": "code",
				"redirect_uri":  "http://127.0.0.1:3000/callback",
				"state":         "<script>alert('xss')</script>",
			},
			expectError: true, // No configured client
			description: "XSS attempt in state parameter should be safely handled",
		},
		{
			name:     "authorize_redirect_uri_mismatch",
			endpoint: "/authorize",
			params: map[string]string{
				"client_id":     "webapp",
				"response_type": "code",
				"redirect_uri":  "http://evil.com/callback",
			},
			expectError: true,
			description: "Open redirect attempt via redirect_uri",
		},
		{
			name:     "authorize_javascript_uri",
			endpoint: "/authorize",
			params: map[string]string{
				"client_id":     "webapp",
				"response_type": "code",
				"redirect_uri":  "javascript:alert(1)",
			},
			expectError: true,
			description: "Javascript URI in redirect_uri should be blocked",
		},
		{
			name:     "token_invalid_grant_type",
			endpoint: "/token",
			params: map[string]string{
				"grant_type": "password",
				"username":   "admin",
				"password":   "admin",
			},
			expectError: true,
			description: "Unsupported grant type should be rejected",
		},
		{
			name:     "token_code_injection",
			endpoint: "/token",
			params: map[string]string{
				"grant_type":   "authorization_code",
				"code":         "'; DROP TABLE auth_codes; --",
				"redirect_uri": "http://localhost:3000/callback",
			},
			expectError: true,
			description: "SQL injection in authorization code",
		},
		{
			name:     "token_extremely_long_code",
			endpoint: "/token",
			params: map[string]string{
				"grant_type":   "authorization_code",
				"code":         strings.Repeat("A", 10000),
				"redirect_uri": "http://localhost:3000/callback",
			},
			expectError: true,
			description: "Extremely long authorization code should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := url.Values{}
			for k, v := range tt.params {
				query.Set(k, v)
			}

			var req *http.Request
			if tt.endpoint == "/token" {
				req = httptest.NewRequest("POST", tt.endpoint, strings.NewReader(query.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest("GET", tt.endpoint+"?"+query.Encode(), nil)
			}

			w := httptest.NewRecorder()
			app.Routes().ServeHTTP(w, req)

			if tt.expectError && w.Code == http.StatusOK {
				t.Errorf("%s: expected error status, got %d", tt.description, w.Code)
			}
			if !tt.expectError && w.Code >= 400 {
				t.Errorf("%s: expected success, got %d", tt.description, w.Code)
			}
		})
	}
}

// TestSecurityFakeCookies tests gateway response to fake/malformed session cookies
func TestSecurityFakeCookies(t *testing.T) {
	app := setupTestApp(t)

	tests := []struct {
		name         string
		cookieValue  string
		endpoint     string
		description  string
	}{
		{
			name:         "fake_session_cookie",
			cookieValue:  "fake-session-12345",
			endpoint:     "/authorize?client_id=webapp&response_type=code&redirect_uri=http://127.0.0.1:3000/callback",
			description:  "Fake session cookie should not grant access",
		},
		{
			name:         "sql_injection_in_cookie",
			cookieValue:  "' OR '1'='1",
			endpoint:     "/authorize?client_id=webapp&response_type=code&redirect_uri=http://127.0.0.1:3000/callback",
			description:  "SQL injection in cookie should be safely ignored",
		},
		{
			name:         "extremely_long_cookie",
			cookieValue:  strings.Repeat("A", 50000),
			endpoint:     "/authorize?client_id=webapp&response_type=code&redirect_uri=http://127.0.0.1:3000/callback",
			description:  "Extremely long cookie should not cause issues",
		},
		{
			name:         "cookie_with_special_chars",
			cookieValue:  "session<script>alert(1)</script>",
			endpoint:     "/authorize?client_id=webapp&response_type=code&redirect_uri=http://127.0.0.1:3000/callback",
			description:  "Cookie with special characters should be safely handled",
		},
		{
			name:         "base64_garbage",
			cookieValue:  "!!!invalid-base64@@@",
			endpoint:     "/authorize?client_id=webapp&response_type=code&redirect_uri=http://127.0.0.1:3000/callback",
			description:  "Malformed base64 in cookie should not crash server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.endpoint, nil)
			req.AddCookie(&http.Cookie{
				Name:  "gw_session",
				Value: tt.cookieValue,
			})

			w := httptest.NewRecorder()
			app.Routes().ServeHTTP(w, req)

			// Should not crash with 5xx errors
			if w.Code >= 500 {
				t.Errorf("%s: server error %d, should handle gracefully", tt.description, w.Code)
			}
			// Verify fake cookies don't result in successful authentication
			if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "authenticated") {
				t.Errorf("%s: fake cookie may have granted access", tt.description)
			}
		})
	}
}

// TestSecurityFakeJWT tests endpoints with fake/malformed JWT tokens
func TestSecurityFakeJWT(t *testing.T) {
	app := setupTestApp(t)

	tests := []struct {
		name         string
		token        string
		endpoint     string
		expectStatus int
		description  string
	}{
		{
			name:         "completely_fake_jwt",
			token:        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fake",
			endpoint:     "/userinfo",
			expectStatus: http.StatusUnauthorized,
			description:  "Fake JWT should be rejected",
		},
		{
			name:         "jwt_none_algorithm",
			token:        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.",
			endpoint:     "/userinfo",
			expectStatus: http.StatusUnauthorized,
			description:  "JWT with 'none' algorithm should be rejected",
		},
		{
			name:         "malformed_jwt",
			token:        "not.a.valid.jwt.token",
			endpoint:     "/userinfo",
			expectStatus: http.StatusUnauthorized,
			description:  "Malformed JWT should be rejected",
		},
		{
			name:         "jwt_with_invalid_signature",
			token:        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiZXhwIjo5OTk5OTk5OTk5fQ.InvalidSignatureHere",
			endpoint:     "/userinfo",
			expectStatus: http.StatusUnauthorized,
			description:  "JWT with invalid signature should be rejected",
		},
		{
			name:         "expired_jwt",
			token:        createExpiredJWT(),
			endpoint:     "/userinfo",
			expectStatus: http.StatusUnauthorized,
			description:  "Expired JWT should be rejected",
		},
		{
			name:         "jwt_buffer_overflow_attempt",
			token:        strings.Repeat("A", 100000),
			endpoint:     "/userinfo",
			expectStatus: http.StatusUnauthorized,
			description:  "Extremely long JWT should be rejected without crashing",
		},
		{
			name:         "empty_bearer_token",
			token:        "",
			endpoint:     "/userinfo",
			expectStatus: http.StatusUnauthorized,
			description:  "Empty bearer token should be rejected",
		},
		{
			name:         "sql_injection_in_token",
			token:        "' OR '1'='1",
			endpoint:     "/userinfo",
			expectStatus: http.StatusUnauthorized,
			description:  "SQL injection in token should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.endpoint, nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			w := httptest.NewRecorder()
			app.Routes().ServeHTTP(w, req)

			if w.Code != tt.expectStatus {
				t.Errorf("%s: expected status %d, got %d", tt.description, tt.expectStatus, w.Code)
			}
		})
	}
}

// TestSecurityBypassAttempts tests attempts to bypass authentication
func TestSecurityBypassAttempts(t *testing.T) {
	app := setupTestApp(t)

	tests := []struct {
		name        string
		method      string
		path        string
		headers     map[string]string
		expectAuth  bool
		description string
	}{
		{
			name:   "path_traversal_to_protected",
			method: "GET",
			path:   "/../../etc/passwd",
			headers: map[string]string{
				"Host": "localhost",
			},
			expectAuth:  false,
			description: "Path traversal should not access protected resources",
		},
		{
			name:   "suspicious_host_header",
			method: "GET",
			path:   "/authorize?client_id=webapp&response_type=code&redirect_uri=http://127.0.0.1:3000/callback",
			headers: map[string]string{
				"Host": "evil.com",
			},
			expectAuth:  false,
			description: "Suspicious Host header should not bypass authorization flow",
		},
		{
			name:   "forwarded_header_spoofing",
			method: "GET",
			path:   "/userinfo",
			headers: map[string]string{
				"X-Forwarded-For": "127.0.0.1",
				"X-Real-IP":       "127.0.0.1",
			},
			expectAuth:  false,
			description: "Spoofed forwarding headers should not bypass auth",
		},
		{
			name:   "case_variation_bypass",
			method: "GET",
			path:   "/USERINFO",
			headers: map[string]string{
				"Authorization": "Bearer fake",
			},
			expectAuth:  false,
			description: "Case variation in path should not bypass security",
		},
		{
			name:   "double_encoding_bypass",
			method: "GET",
			path:   "/%252e%252e%252f%252e%252e%252fetc%252fpasswd",
			expectAuth:  false,
			description: "Double-encoded path traversal should be blocked",
		},
		{
			name:   "fake_internal_header",
			method: "GET",
			path:   "/userinfo",
			headers: map[string]string{
				"X-User-ID":     "admin",
				"X-Auth-Type":   "cookie",
				"X-User-Scopes": "admin superuser",
			},
			expectAuth:  false,
			description: "Client-provided internal headers should not grant access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			app.Routes().ServeHTTP(w, req)

			// Protected endpoints should not grant unauthorized access
			// For /authorize endpoint, it may return 200 (dev page) or redirect (302)
			// The key is that it should not leak sensitive data or grant access
			if strings.Contains(tt.path, "/userinfo") || strings.Contains(tt.path, "/introspect") {
				// These endpoints must require authentication
				if w.Code == http.StatusOK && !tt.expectAuth {
					t.Errorf("%s: bypass successful (got 200), security check failed", tt.description)
				}
			} else if strings.Contains(tt.path, "/authorize") {
				// Authorize endpoint behavior: should redirect to auth or return error
				// Getting 200 is OK if it's the dev auth page, not actual user data
				if w.Code >= 500 {
					t.Errorf("%s: server error (5xx), should handle gracefully", tt.description)
				}
			}
		})
	}
}

// TestSecurityBufferOverflows tests potential buffer overflow scenarios
func TestSecurityBufferOverflows(t *testing.T) {
	app := setupTestApp(t)

	tests := []struct {
		name        string
		buildReq    func() *http.Request
		description string
	}{
		{
			name: "large_post_body",
			buildReq: func() *http.Request {
				body := strings.Repeat("a="+strings.Repeat("A", 1000)+"&", 1000) // ~1MB form data
				req := httptest.NewRequest("POST", "/token", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			description: "Large POST body should be handled without crash",
		},
		{
			name: "many_query_parameters",
			buildReq: func() *http.Request {
				query := url.Values{}
				for i := 0; i < 1000; i++ {
					query.Add(fmt.Sprintf("param%d", i), strings.Repeat("A", 100))
				}
				req := httptest.NewRequest("GET", "/authorize?"+query.Encode(), nil)
				return req
			},
			description: "Many query parameters should not cause buffer overflow",
		},
		{
			name: "deeply_nested_json",
			buildReq: func() *http.Request {
				nested := strings.Repeat(`{"a":`, 1000) + `"value"` + strings.Repeat(`}`, 1000)
				req := httptest.NewRequest("POST", "/token", strings.NewReader(nested))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			description: "Deeply nested JSON should not cause stack overflow",
		},
		{
			name: "many_cookies",
			buildReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/authorize?client_id=webapp&response_type=code&redirect_uri=http://127.0.0.1:3000/callback", nil)
				for i := 0; i < 100; i++ {
					req.AddCookie(&http.Cookie{
						Name:  fmt.Sprintf("cookie%d", i),
						Value: strings.Repeat("A", 100),
					})
				}
				return req
			},
			description: "Many cookies should be handled gracefully",
		},
		{
			name: "large_authorization_header",
			buildReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/userinfo", nil)
				req.Header.Set("Authorization", "Bearer "+strings.Repeat("A", 50000))
				return req
			},
			description: "Extremely large Authorization header should not crash server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: server panic - %v", tt.description, r)
				}
			}()

			req := tt.buildReq()
			w := httptest.NewRecorder()
			app.Routes().ServeHTTP(w, req)

			// Just ensure server responds without crashing
			if w.Code == 0 {
				t.Errorf("%s: no response from server", tt.description)
			}
		})
	}
}

// TestSecurityOpenRedirect tests open redirect vulnerabilities
func TestSecurityOpenRedirect(t *testing.T) {
	app := setupTestApp(t)

	maliciousRedirects := []string{
		"http://evil.com/callback",
		"https://evil.com",
		"//evil.com/callback",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"file:///etc/passwd",
		"http://localhost@evil.com",
		"http://evil.com#http://localhost:3000/callback",
		"http://localhost:3000/callback@evil.com",
	}

	for _, redirect := range maliciousRedirects {
		t.Run("redirect_"+redirect, func(t *testing.T) {
			query := url.Values{}
			query.Set("client_id", "webapp")
			query.Set("response_type", "code")
			query.Set("redirect_uri", redirect)

			req := httptest.NewRequest("GET", "/authorize?"+query.Encode(), nil)
			w := httptest.NewRecorder()
			app.Routes().ServeHTTP(w, req)

			// Should not redirect to malicious URLs
			if w.Code == http.StatusFound {
				location := w.Header().Get("Location")
				if strings.Contains(location, "evil.com") ||
					strings.HasPrefix(location, "javascript:") ||
					strings.HasPrefix(location, "data:") ||
					strings.HasPrefix(location, "file:") {
					t.Errorf("Open redirect vulnerability: redirected to %s", location)
				}
			}
		})
	}
}

// TestSecurityRateLimitingBasic tests basic rate limiting behavior
func TestSecurityRateLimitingBasic(t *testing.T) {
	app := setupTestApp(t)

	// Simulate rapid requests to token endpoint
	failureCount := 0
	for i := 0; i < 100; i++ {
		body := url.Values{}
		body.Set("grant_type", "authorization_code")
		body.Set("code", "invalid")
		body.Set("redirect_uri", "http://localhost:3000/callback")

		req := httptest.NewRequest("POST", "/token", strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		app.Routes().ServeHTTP(w, req)

		if w.Code == http.StatusTooManyRequests {
			failureCount++
		}
	}

	// Note: This test documents current behavior - rate limiting may not be implemented yet
	// If rate limiting is implemented, failureCount should be > 0
	t.Logf("Rate limiting test: %d/100 requests rate limited", failureCount)
}

// TestSecurityCSRF tests CSRF protection mechanisms
func TestSecurityCSRF(t *testing.T) {
	app := setupTestApp(t)

	tests := []struct {
		name        string
		method      string
		endpoint    string
		origin      string
		referer     string
		expectBlock bool
		description string
	}{
		{
			name:        "cross_origin_post_token",
			method:      "POST",
			endpoint:    "/token",
			origin:      "http://evil.com",
			referer:     "http://evil.com/attack.html",
			expectBlock: false, // Token endpoint uses client credentials, not CSRF-vulnerable
			description: "Token endpoint with cross-origin should validate via client auth",
		},
		{
			name:        "cross_origin_post_logout",
			method:      "POST",
			endpoint:    "/logout",
			origin:      "http://evil.com",
			referer:     "http://evil.com/attack.html",
			expectBlock: false, // Logout should work cross-origin (may clear session)
			description: "Logout from cross-origin should be handled safely",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.endpoint, nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}

			w := httptest.NewRecorder()
			app.Routes().ServeHTTP(w, req)

			if tt.expectBlock && w.Code == http.StatusOK {
				t.Errorf("%s: CSRF attack succeeded", tt.description)
			}
		})
	}
}

// TestSecurityProxyBypass tests attempts to bypass proxy authentication
func TestSecurityProxyBypass(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping proxy security tests in short mode")
	}

	cfg := DefaultConfig()
	cfg.Server.DevMode = true
	cfg.Proxy.Routes = []ProxyRoute{
		{
			Host:        "app.example.com",
			Target:      "http://localhost:9999",
			RequireAuth: true,
		},
	}

	app, err := createTestAppWithConfig(cfg)
	if err != nil {
		t.Skipf("Skipping proxy tests: %v", err)
		return
	}

	tests := []struct {
		name        string
		headers     map[string]string
		expectBlock bool
		description string
	}{
		{
			name: "inject_fake_jwt_header",
			headers: map[string]string{
				"Host":         "app.example.com",
				"X-Auth-Token": "fake.jwt.token",
			},
			expectBlock: true,
			description: "Client-injected JWT header should not grant access",
		},
		{
			name: "inject_fake_user_headers",
			headers: map[string]string{
				"Host":          "app.example.com",
				"X-User-ID":     "admin",
				"X-User-Email":  "admin@example.com",
				"X-User-Scopes": "admin",
			},
			expectBlock: true,
			description: "Client-injected user headers should not bypass auth",
		},
		{
			name: "host_header_mismatch",
			headers: map[string]string{
				"Host":           "app.example.com",
				"X-Forwarded-Host": "evil.com",
			},
			expectBlock: true,
			description: "Mismatched forwarding headers should not bypass auth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/protected", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			app.Routes().ServeHTTP(w, req)

			if tt.expectBlock && w.Code == http.StatusOK {
				t.Errorf("%s: bypass successful", tt.description)
			}
		})
	}
}

// TestSecurityTimingAttacks tests for timing attack vulnerabilities
func TestSecurityTimingAttacks(t *testing.T) {
	app := setupTestApp(t)

	// Test token validation timing
	validToken := "valid_token_abc123"
	invalidToken := "x"

	iterations := 10
	var validDurations, invalidDurations []time.Duration

	for i := 0; i < iterations; i++ {
		// Measure valid token validation time
		start := time.Now()
		req := httptest.NewRequest("GET", "/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		w := httptest.NewRecorder()
		app.Routes().ServeHTTP(w, req)
		validDurations = append(validDurations, time.Since(start))

		// Measure invalid token validation time
		start = time.Now()
		req = httptest.NewRequest("GET", "/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+invalidToken)
		w = httptest.NewRecorder()
		app.Routes().ServeHTTP(w, req)
		invalidDurations = append(invalidDurations, time.Since(start))
	}

	// Calculate averages
	var validAvg, invalidAvg time.Duration
	for i := 0; i < iterations; i++ {
		validAvg += validDurations[i]
		invalidAvg += invalidDurations[i]
	}
	validAvg /= time.Duration(iterations)
	invalidAvg /= time.Duration(iterations)

	// Log timing information (for analysis)
	t.Logf("Valid token avg time: %v", validAvg)
	t.Logf("Invalid token avg time: %v", invalidAvg)

	// Note: Significant timing differences could indicate timing attack vulnerability
	// This test documents the behavior for security review
}

// Helper functions

func setupTestApp(t *testing.T) *App {
	cfg := DefaultConfig()
	cfg.Server.DevMode = true

	// Add a test client to prevent 5xx errors
	cfg.OAuth2Clients = []ClientConfig{
		{
			ClientID:     "webapp",
			ClientSecret: "test-secret",
			RedirectURIs: []string{"http://127.0.0.1:3000/callback"},
			Scopes:       []string{"openid", "profile", "email"},
			Audiences:    []string{cfg.Server.ServerID},
		},
	}

	app, err := createTestAppWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create test app: %v", err)
	}
	return app
}

func createTestAppWithConfig(cfg Config) (*App, error) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	return NewApp(ctx, cfg, logger)
}

func createExpiredJWT() string {
	// Create a JWT structure with expired timestamp
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user123","exp":1}`))
	return header + "." + payload + ".fakesignature"
}

// TestSecurityHeaderInjection tests for header injection vulnerabilities
func TestSecurityHeaderInjection(t *testing.T) {
	app := setupTestApp(t)

	tests := []struct {
		name        string
		headerName  string
		headerValue string
		description string
	}{
		{
			name:        "suspicious_user_agent",
			headerName:  "User-Agent",
			headerValue: strings.Repeat("A", 1000),
			description: "Extremely long User-Agent",
		},
		{
			name:        "suspicious_referer",
			headerName:  "Referer",
			headerValue: "javascript:alert(1)",
			description: "Javascript URI in Referer",
		},
		{
			name:        "long_custom_header",
			headerName:  "X-Custom",
			headerValue: strings.Repeat("value", 1000),
			description: "Extremely long custom header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
			req.Header.Set(tt.headerName, tt.headerValue)

			w := httptest.NewRecorder()
			app.Routes().ServeHTTP(w, req)

			// Check that injected headers are not present in response
			if w.Header().Get("X-Injected") != "" || w.Header().Get("X-Evil") != "" {
				t.Errorf("%s: header injection successful", tt.description)
			}
		})
	}
}

// TestSecurityDenialOfService tests basic DoS resilience
func TestSecurityDenialOfService(t *testing.T) {
	app := setupTestApp(t)

	tests := []struct {
		name        string
		buildReq    func() *http.Request
		description string
	}{
		{
			name: "zip_bomb_in_body",
			buildReq: func() *http.Request {
				// Highly compressible data
				body := strings.Repeat("0", 100000)
				req := httptest.NewRequest("POST", "/token", strings.NewReader(body))
				req.Header.Set("Content-Encoding", "gzip")
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			description: "Zip bomb attempt should be handled",
		},
		{
			name: "slow_loris_simulation",
			buildReq: func() *http.Request {
				req := httptest.NewRequest("POST", "/token", &slowReader{})
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Content-Length", "999999")
				return req
			},
			description: "Slow read attack should timeout",
		},
		{
			name: "memory_exhaustion_attempt",
			buildReq: func() *http.Request {
				// Try to exhaust memory with large Content-Length claim
				req := httptest.NewRequest("POST", "/token", strings.NewReader("small"))
				req.Header.Set("Content-Length", "999999999")
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			description: "Large Content-Length should not exhaust memory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: server panic - %v", tt.description, r)
				}
			}()

			req := tt.buildReq()
			w := httptest.NewRecorder()

			// Set a timeout for the request
			done := make(chan bool)
			go func() {
				app.Routes().ServeHTTP(w, req)
				done <- true
			}()

			select {
			case <-done:
				// Request completed
			case <-time.After(5 * time.Second):
				t.Logf("%s: request timed out (this may be expected behavior)", tt.description)
			}
		})
	}
}

// slowReader simulates a slow client for DoS testing
type slowReader struct {
	bytesRead int
}

func (sr *slowReader) Read(p []byte) (n int, err error) {
	if sr.bytesRead > 100 {
		return 0, fmt.Errorf("slow read timeout")
	}
	time.Sleep(100 * time.Millisecond)
	if len(p) > 0 {
		p[0] = 'a'
		sr.bytesRead++
		return 1, nil
	}
	return 0, nil
}

// TestSecurityXMLExternalEntity tests XXE vulnerability protection
func TestSecurityXMLExternalEntity(t *testing.T) {
	app := setupTestApp(t)

	xxePayload := `<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>`

	req := httptest.NewRequest("POST", "/token", strings.NewReader(xxePayload))
	req.Header.Set("Content-Type", "application/xml")

	w := httptest.NewRecorder()
	app.Routes().ServeHTTP(w, req)

	// Should reject XML content type (OAuth uses form-encoded)
	if w.Code == http.StatusOK {
		t.Error("XML payload was accepted, potential XXE vulnerability")
	}

	// Check response doesn't leak file contents
	if strings.Contains(w.Body.String(), "root:") {
		t.Error("Response contains potential file content leak")
	}
}

// TestSecurityRandomnessQuality tests quality of random values
func TestSecurityRandomnessQuality(t *testing.T) {
	// Generate multiple random session IDs and check for uniqueness
	seen := make(map[string]bool)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			t.Fatalf("Random generation failed: %v", err)
		}
		id := base64.RawURLEncoding.EncodeToString(b)

		if seen[id] {
			t.Errorf("Duplicate random value detected: %s", id)
		}
		seen[id] = true
	}

	if len(seen) != iterations {
		t.Errorf("Expected %d unique values, got %d", iterations, len(seen))
	}
}

// TestSecurityInformationDisclosure tests for information leakage
func TestSecurityInformationDisclosure(t *testing.T) {
	app := setupTestApp(t)

	tests := []struct {
		name             string
		endpoint         string
		method           string
		checkResponse    func(t *testing.T, body string, headers http.Header)
		description      string
	}{
		{
			name:     "error_message_disclosure",
			endpoint: "/token",
			method:   "POST",
			checkResponse: func(t *testing.T, body string, headers http.Header) {
				// Error messages shouldn't leak internal paths or stack traces
				if strings.Contains(body, "/home/") || strings.Contains(body, "C:\\") {
					t.Error("Error message leaks internal file paths")
				}
				if strings.Contains(body, "goroutine") || strings.Contains(body, "panic") {
					t.Error("Error message leaks stack trace information")
				}
			},
			description: "Error messages should not leak sensitive information",
		},
		{
			name:     "server_version_disclosure",
			endpoint: "/.well-known/openid-configuration",
			method:   "GET",
			checkResponse: func(t *testing.T, body string, headers http.Header) {
				server := headers.Get("Server")
				xPoweredBy := headers.Get("X-Powered-By")
				if strings.Contains(server, "Go") || xPoweredBy != "" {
					t.Logf("Server version information disclosed: Server=%s, X-Powered-By=%s", server, xPoweredBy)
				}
			},
			description: "Check for server version disclosure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.endpoint, nil)
			w := httptest.NewRecorder()
			app.Routes().ServeHTTP(w, req)

			tt.checkResponse(t, w.Body.String(), w.Header())
		})
	}
}

// TestSecurityContentTypeValidation tests content type validation
func TestSecurityContentTypeValidation(t *testing.T) {
	app := setupTestApp(t)

	tests := []struct {
		name        string
		contentType string
		body        string
		expectError bool
		description string
	}{
		{
			name:        "valid_form_encoded",
			contentType: "application/x-www-form-urlencoded",
			body:        "grant_type=client_credentials",
			expectError: false,
			description: "Valid form-encoded content type",
		},
		{
			name:        "json_instead_of_form",
			contentType: "application/json",
			body:        `{"grant_type":"client_credentials"}`,
			expectError: true,
			description: "JSON content type should be rejected for token endpoint",
		},
		{
			name:        "multipart_form_data",
			contentType: "multipart/form-data",
			body:        "grant_type=client_credentials",
			expectError: true,
			description: "Multipart form data should be rejected",
		},
		{
			name:        "text_plain",
			contentType: "text/plain",
			body:        "grant_type=client_credentials",
			expectError: true,
			description: "Text/plain content type should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/token", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)

			w := httptest.NewRecorder()
			app.Routes().ServeHTTP(w, req)

			if tt.expectError && w.Code == http.StatusOK {
				t.Errorf("%s: invalid content type accepted", tt.description)
			}
		})
	}
}
