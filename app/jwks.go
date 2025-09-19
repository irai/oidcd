package app

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
)

type keyPair struct {
	PrivateKey *rsa.PrivateKey
	JWK        jose.JSONWebKey
	Kid        string
	CreatedAt  time.Time
}

// JWKSManager manages signing keys and JSON Web Key Set exposure.
type JWKSManager struct {
	mu          sync.RWMutex
	current     keyPair
	previous    []keyPair
	rotateEvery time.Duration
	storePath   string
	logger      *slog.Logger
}

// NewJWKSManager loads or creates signing keys.
func NewJWKSManager(cfg KeyConfig, logger *slog.Logger) (*JWKSManager, error) {
	manager := &JWKSManager{
		rotateEvery: cfg.RotateInterval,
		storePath:   cfg.JWKSPath,
		logger:      logger,
	}

	if cfg.JWKSPath != "" {
		if err := manager.loadFromDisk(); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
	}

	if manager.current.PrivateKey == nil {
		if err := manager.rotate(); err != nil {
			return nil, err
		}
	}

	return manager, nil
}

// StartRotation launches background rotation ticker.
func (m *JWKSManager) StartRotation(stop <-chan struct{}) {
	if m.rotateEvery <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(m.rotateEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := m.rotate(); err != nil {
					m.logger.Error("jwks rotate", "error", err)
				}
			case <-stop:
				return
			}
		}
	}()
}

// Sign signs claims and returns token string with kid.
func (m *JWKSManager) Sign(claims jwt.MapClaims) (string, string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	m.mu.RLock()
	defer m.mu.RUnlock()
	token.Header["kid"] = m.current.Kid
	signed, err := token.SignedString(m.current.PrivateKey)
	if err != nil {
		return "", "", err
	}
	return signed, m.current.Kid, nil
}

// Keyfunc is used during JWT validation.
func (m *JWKSManager) Keyfunc(token *jwt.Token) (any, error) {
	kid, _ := token.Header["kid"].(string)
	m.mu.RLock()
	defer m.mu.RUnlock()
	if kid == "" || kid == m.current.Kid {
		return &m.current.PrivateKey.PublicKey, nil
	}
	for _, prev := range m.previous {
		if prev.Kid == kid {
			return &prev.PrivateKey.PublicKey, nil
		}
	}
	return &m.current.PrivateKey.PublicKey, nil
}

// PublicJWKS exposes public keys for JWKS endpoint.
func (m *JWKSManager) PublicJWKS() jose.JSONWebKeySet {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := []jose.JSONWebKey{
		m.current.JWK.Public(),
	}
	for _, prev := range m.previous {
		keys = append(keys, prev.JWK.Public())
	}
	return jose.JSONWebKeySet{Keys: keys}
}

func (m *JWKSManager) rotate() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	kid := randomKID()
	jwk := jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}

	m.mu.Lock()
	if m.current.PrivateKey != nil {
		m.previous = append([]keyPair{m.current}, m.previous...)
		if len(m.previous) > 1 {
			m.previous = m.previous[:1]
		}
	}
	m.current = keyPair{PrivateKey: key, JWK: jwk, Kid: kid, CreatedAt: time.Now()}
	m.mu.Unlock()

	if m.storePath != "" {
		if err := m.persist(); err != nil {
			return err
		}
	}
	return nil
}

func (m *JWKSManager) persist() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := []jose.JSONWebKey{m.current.JWK}
	for _, prev := range m.previous {
		keys = append(keys, prev.JWK)
	}
	payload, err := json.MarshalIndent(jose.JSONWebKeySet{Keys: keys}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.storePath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(m.storePath, payload, 0o600)
}

func (m *JWKSManager) loadFromDisk() error {
	payload, err := os.ReadFile(m.storePath)
	if err != nil {
		return err
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(payload, &set); err != nil {
		return err
	}
	if len(set.Keys) == 0 {
		return errors.New("no keys in jwks")
	}
	var prev []keyPair
	for i, key := range set.Keys {
		priv, ok := key.Key.(*rsa.PrivateKey)
		if !ok {
			continue
		}
		pair := keyPair{PrivateKey: priv, JWK: key, Kid: key.KeyID, CreatedAt: time.Now()}
		if i == 0 {
			m.current = pair
		} else {
			prev = append(prev, pair)
		}
	}
	m.previous = prev
	return nil
}

func randomKID() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "kid"
	}
	return hexEncode(buf)
}

func hexEncode(b []byte) string {
	alphabet := "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = alphabet[v>>4]
		out[i*2+1] = alphabet[v&0x0f]
	}
	return string(out)
}
