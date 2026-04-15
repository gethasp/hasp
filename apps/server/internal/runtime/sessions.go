package runtime

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	currentUserFn = user.Current
	gitTopLevelFn = func(abs string) ([]byte, error) {
		return exec.Command("git", "-C", abs, "rev-parse", "--show-toplevel").Output()
	}
	randomRead  = rand.Read
	filepathAbs = filepath.Abs
)

type Session struct {
	ID          string
	Token       string
	LocalUser   string
	HostLabel   string
	ProjectRoot string
	ExpiresAt   time.Time
	LastSeenAt  time.Time
}

type SessionView struct {
	ID          string    `json:"id"`
	LocalUser   string    `json:"local_user"`
	HostLabel   string    `json:"host_label"`
	ProjectRoot string    `json:"project_root"`
	ExpiresAt   time.Time `json:"expires_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]Session
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]Session)}
}

func (s *SessionStore) Open(hostLabel, projectRoot string, ttl time.Duration) (Session, error) {
	if ttl <= 0 {
		return Session{}, errors.New("ttl must be positive")
	}
	localUser, err := currentUser()
	if err != nil {
		return Session{}, err
	}
	now := time.Now().UTC()
	session := Session{
		ID:          mustRandomHex(16),
		Token:       mustRandomHex(32),
		LocalUser:   localUser,
		HostLabel:   hostLabel,
		ProjectRoot: CanonicalProjectRoot(projectRoot),
		ExpiresAt:   now.Add(ttl),
		LastSeenAt:  now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.Token] = session
	return session, nil
}

func (s *SessionStore) Resolve(token string) (Session, bool) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[token]
	if !ok {
		return Session{}, false
	}
	if now.After(session.ExpiresAt) {
		delete(s.sessions, token)
		return Session{}, false
	}
	session.LastSeenAt = now
	s.sessions[token] = session
	return session, true
}

func (s *SessionStore) Revoke(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[token]; !ok {
		return false
	}
	delete(s.sessions, token)
	return true
}

func (s *SessionStore) ActiveCount() int {
	s.PruneExpired()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

func (s *SessionStore) Snapshot() []Session {
	s.PruneExpired()
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		out = append(out, session)
	}
	return out
}

func (s *SessionStore) ViewSnapshot() []SessionView {
	sessions := s.Snapshot()
	out := make([]SessionView, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, session.View())
	}
	return out
}

func (s *SessionStore) PruneExpired() {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, token)
		}
	}
}

func mustRandomHex(n int) string {
	buf := make([]byte, n)
	if _, err := randomRead(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

func CanonicalProjectRoot(path string) string {
	if path == "" {
		return ""
	}
	abs, err := filepathAbs(path)
	if err != nil {
		abs = filepath.Clean(path)
	}
	if out, err := gitTopLevelFn(abs); err == nil {
		abs = strings.TrimSpace(string(out))
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return resolved
	}
	return filepath.Clean(abs)
}

func currentUser() (string, error) {
	u, err := currentUserFn()
	if err != nil {
		return "", err
	}
	if u.Username != "" {
		return u.Username, nil
	}
	return u.Uid, nil
}

func (s Session) View() SessionView {
	return SessionView{
		ID:          s.ID,
		LocalUser:   s.LocalUser,
		HostLabel:   s.HostLabel,
		ProjectRoot: s.ProjectRoot,
		ExpiresAt:   s.ExpiresAt,
		LastSeenAt:  s.LastSeenAt,
	}
}
