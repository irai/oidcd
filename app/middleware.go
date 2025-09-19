package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

var requestIDKey = struct{}{}

// RequestIDMiddleware attaches a request ID for traceability.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = randomID()
		}
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey, reqID))
		w.Header().Set("X-Request-ID", reqID)
		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware emits structured request logs using slog.
func LoggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			dur := time.Since(start)

			reqID := RequestIDFromContext(r.Context())
			attrs := []any{
				"request_id", reqID,
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration_ms", dur.Milliseconds(),
			}
			if clientID := r.FormValue("client_id"); clientID != "" {
				attrs = append(attrs, "client_id", clientID)
			}
			if sub := SubjectFromContext(r.Context()); sub != "" {
				attrs = append(attrs, "user_sub", sub)
			}
			if idp := IDPFromContext(r.Context()); idp != "" {
				attrs = append(attrs, "idp", idp)
			}

			logger.Info("http_request", attrs...)
		})
	}
}

// RecoveryMiddleware guards against panics and surfaces stack traces in dev.
func RecoveryMiddleware(logger *slog.Logger, dev bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Error("panic", "error", err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// CORSMiddleware applies configured CORS policy.
func CORSMiddleware(cfg CORSConfig) func(http.Handler) http.Handler {
	allowedMethods := strings.Join(cfg.AllowedMethods, ", ")
	allowedHeaders := strings.Join(cfg.AllowedHeaders, ", ")
	allowedOrigins := cfg.ClientOriginURLs

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && originAllowed(origin, allowedOrigins) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
				w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeadersMiddleware enforces HSTS in production.
func SecurityHeadersMiddleware(maxAge int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS != nil {
				w.Header().Set("Strict-Transport-Security",
					fmt.Sprintf("max-age=%d; includeSubDomains", maxAge))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequestIDFromContext extracts the request ID.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

func originAllowed(origin string, allowed []string) bool {
	for _, v := range allowed {
		if v == "*" || v == origin {
			return true
		}
	}
	return false
}

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func randomID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(buf)
}

// SubjectFromContext returns the subject claim stored on the context.
func SubjectFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(subjectKey{}).(string); ok {
		return v
	}
	return ""
}

// IDPFromContext returns the upstream provider stored on the context.
func IDPFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(idpKey{}).(string); ok {
		return v
	}
	return ""
}

type subjectKey struct{}
type idpKey struct{}
