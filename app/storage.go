package app

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// AuthRequest tracks outstanding upstream authentication requests.
type AuthRequest struct {
	ID                  string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Provider            string
	Audience            string
	CreatedAt           time.Time
	PKCERequired        bool
}

// UserProfile retains minimal profile data for /userinfo replies.
type UserProfile struct {
	Subject string
	Email   string
	Name    string
}

// InMemoryStore keeps ephemeral state for tokens, sessions, and codes.
type InMemoryStore struct {
	mu            sync.RWMutex
	sessions      map[string]Session
	authCodes     map[string]AuthorizationCode
	authRequests  map[string]AuthRequest
	refreshTokens map[string]RefreshToken
	userProfiles  map[string]*UserProfile
	jtiBlacklist  map[string]time.Time
}

// NewInMemoryStore constructs the store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		sessions:      make(map[string]Session),
		authCodes:     make(map[string]AuthorizationCode),
		authRequests:  make(map[string]AuthRequest),
		refreshTokens: make(map[string]RefreshToken),
		userProfiles:  make(map[string]*UserProfile),
		jtiBlacklist:  make(map[string]time.Time),
	}
}

// NewID generates a random identifier.
func (s *InMemoryStore) NewID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString([]byte("fallbackid"))
	}
	return hex.EncodeToString(buf)
}

// SaveSession stores or replaces a session.
func (s *InMemoryStore) SaveSession(sess Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
}

// GetSession retrieves a session by ID.
func (s *InMemoryStore) GetSession(id string) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

// DeleteSession removes a session.
func (s *InMemoryStore) DeleteSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// SaveAuthCode persists an authorization code.
func (s *InMemoryStore) SaveAuthCode(code AuthorizationCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authCodes[code.Code] = code
}

// ConsumeAuthCode fetches and removes an authorization code.
func (s *InMemoryStore) ConsumeAuthCode(code string) (AuthorizationCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	auth, ok := s.authCodes[code]
	if !ok {
		return AuthorizationCode{}, false
	}
	if time.Now().After(auth.ExpiresAt) || auth.Used {
		delete(s.authCodes, code)
		return AuthorizationCode{}, false
	}
	auth.Used = true
	delete(s.authCodes, code)
	return auth, true
}

// SaveAuthRequest stores an upstream auth request awaiting callback.
func (s *InMemoryStore) SaveAuthRequest(req AuthRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authRequests[req.ID] = req
}

// ConsumeAuthRequest retrieves and removes an auth request.
func (s *InMemoryStore) ConsumeAuthRequest(id string) (AuthRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.authRequests[id]
	if !ok {
		return AuthRequest{}, false
	}
	delete(s.authRequests, id)
	return req, true
}

// SaveRefreshToken stores or replaces a refresh token record.
func (s *InMemoryStore) SaveRefreshToken(rt RefreshToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[rt.ID] = rt
}

// GetRefreshToken fetches a refresh token by ID.
func (s *InMemoryStore) GetRefreshToken(id string) (RefreshToken, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rt, ok := s.refreshTokens[id]
	return rt, ok
}

// DeleteRefreshToken removes a refresh token from store.
func (s *InMemoryStore) DeleteRefreshToken(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refreshTokens, id)
}

// RememberUserProfile stores minimal profile information.
func (s *InMemoryStore) RememberUserProfile(provider string, user ProviderUser) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := provider + ":" + user.Subject
	s.userProfiles[key] = &UserProfile{Subject: key, Email: user.Email, Name: user.Name}
}

// LookupUserProfile returns profile info if stored.
func (s *InMemoryStore) LookupUserProfile(sub string) *UserProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.userProfiles[sub]
}

// BlacklistJTI stores a JWT ID until provided expiry.
func (s *InMemoryStore) BlacklistJTI(jti string, until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jtiBlacklist[jti] = until
}

// JTIBlacklisted indicates if jti is revoked.
func (s *InMemoryStore) JTIBlacklisted(jti string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.jtiBlacklist[jti]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(s.jtiBlacklist, jti)
		return false
	}
	return true
}
