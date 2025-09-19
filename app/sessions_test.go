package app

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionManagerCreateSetsCookie(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Sessions.TTL = time.Hour

	store := NewInMemoryStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewSessionManager(cfg, store, logger)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	user := ProviderUser{Subject: "user-123", Email: "user@example.com"}
	sess, err := manager.Create(w, r, "stub", user)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if sess.UserID != "stub:user-123" {
		t.Fatalf("unexpected user id: %q", sess.UserID)
	}

	resp := w.Result()
	cookie := resp.Cookies()
	if len(cookie) == 0 {
		t.Fatalf("expected cookie to be set")
	}
	found := false
	for _, c := range cookie {
		if c.Name == sessionCookieName && c.Value == sess.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("session cookie missing")
	}
}

func TestSessionManagerFetchExtendsExpiry(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Sessions.TTL = time.Minute

	store := NewInMemoryStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewSessionManager(cfg, store, logger)

	sess := Session{
		ID:        "session",
		UserID:    "stub:user",
		IDP:       "stub",
		ExpiresAt: time.Now().Add(10 * time.Second),
	}
	store.SaveSession(sess)

	req := httptest.NewRequest("GET", "/profile", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})

	returned, err := manager.Fetch(req)
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}
	if returned == nil {
		t.Fatalf("expected session to be returned")
	}
	if !returned.ExpiresAt.After(time.Now().Add(30 * time.Second)) {
		t.Fatalf("expected sliding expiration to extend session")
	}
}

func TestSessionManagerFetchExpired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Sessions.TTL = time.Minute

	store := NewInMemoryStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := NewSessionManager(cfg, store, logger)

	sess := Session{
		ID:        "expired",
		UserID:    "stub:user",
		IDP:       "stub",
		ExpiresAt: time.Now().Add(-time.Second),
	}
	store.SaveSession(sess)

	req := httptest.NewRequest("GET", "/profile", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})

	returned, err := manager.Fetch(req)
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}
	if returned != nil {
		t.Fatalf("expected expired session to be cleared")
	}
	if _, ok := store.GetSession(sess.ID); ok {
		t.Fatalf("expected expired session to be removed from store")
	}
}
