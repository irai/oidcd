package server

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const sessionCookieName = "gw_session"

// SessionManager handles cookie-backed sessions.
type SessionManager struct {
	store        *InMemoryStore
	logger       *slog.Logger
	ttl          time.Duration
	secure       bool
	sameSite     http.SameSite
	cookieDomain string
}

// NewSessionManager constructs a session manager honouring config.
func NewSessionManager(cfg Config, store *InMemoryStore, logger *slog.Logger) *SessionManager {
	sameSite := http.SameSiteStrictMode
	if cfg.Server.DevMode {
		sameSite = http.SameSiteLaxMode
	}
	secure := !cfg.Server.DevMode

	return &SessionManager{
		store:        store,
		logger:       logger,
		ttl:          cfg.Sessions.TTL,
		secure:       secure,
		sameSite:     sameSite,
		cookieDomain: cfg.Server.CookieDomain,
	}
}

// Fetch returns the session associated with the request cookie if present.
func (sm *SessionManager) Fetch(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, nil
	}
	sess, ok := sm.store.GetSession(cookie.Value)
	if !ok {
		return nil, nil
	}
	if time.Now().After(sess.ExpiresAt) {
		sm.store.DeleteSession(sess.ID)
		return nil, nil
	}

	// Sliding expiration: extend on activity.
	sess.ExpiresAt = time.Now().Add(sm.ttl)
	sm.store.SaveSession(sess)
	return &sess, nil
}

// Create establishes a new session and sets the cookie.
func (sm *SessionManager) Create(w http.ResponseWriter, r *http.Request, provider string, user ProviderUser) (*Session, error) {
	id := sm.store.NewID()
	userID := buildUserID(provider, user.Subject)
	sess := Session{
		ID:        id,
		UserID:    userID,
		IDP:       provider,
		AuthTime:  time.Now(),
		ExpiresAt: time.Now().Add(sm.ttl),
	}

	sm.store.SaveSession(sess)
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		Domain:   sm.cookieDomain,
		HttpOnly: true,
		Secure:   sm.secure,
		SameSite: sm.sameSite,
		MaxAge:   int(sm.ttl.Seconds()),
	}
	http.SetCookie(w, cookie)

	return &sess, nil
}

// Clear removes the session cookie for logout.
func (sm *SessionManager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Domain:   sm.cookieDomain,
		HttpOnly: true,
		Secure:   sm.secure,
		SameSite: sm.sameSite,
		MaxAge:   -1,
	})
}

func buildUserID(provider, subject string) string {
	return provider + ":" + strings.TrimSpace(subject)
}
