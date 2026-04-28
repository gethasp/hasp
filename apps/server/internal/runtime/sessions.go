package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/gitsafe"
)

var (
	currentUserFn = user.Current
	gitTopLevelFn = func(abs string) ([]byte, error) {
		out, err := gitsafe.TopLevelCached(context.Background(), abs)
		if err != nil {
			return nil, err
		}
		return []byte(out + "\n"), nil
	}
	randomRead     = rand.Read
	filepathAbs    = filepath.Abs
	evalSymlinksFn = filepath.EvalSymlinks
)

var (
	canonicalRootCacheMu sync.Mutex
	canonicalRootCache   = make(map[string]canonicalRootEntry)
)

type canonicalRootEntry struct {
	inputInfo os.FileInfo
	resolved  string
}

func resetCanonicalRootCache() {
	canonicalRootCacheMu.Lock()
	canonicalRootCache = make(map[string]canonicalRootEntry)
	canonicalRootCacheMu.Unlock()
}

func cachedEvalSymlinks(abs string) (string, bool) {
	info, err := os.Stat(abs)
	if err != nil {
		return "", false
	}
	canonicalRootCacheMu.Lock()
	entry, hit := canonicalRootCache[abs]
	canonicalRootCacheMu.Unlock()
	if hit && os.SameFile(entry.inputInfo, info) {
		return entry.resolved, true
	}
	resolved, err := evalSymlinksFn(abs)
	if err != nil {
		canonicalRootCacheMu.Lock()
		delete(canonicalRootCache, abs)
		canonicalRootCacheMu.Unlock()
		return "", false
	}
	canonicalRootCacheMu.Lock()
	canonicalRootCache[abs] = canonicalRootEntry{inputInfo: info, resolved: resolved}
	canonicalRootCacheMu.Unlock()
	return resolved, true
}

type Session struct {
	ID           string
	Token        string
	LocalUser    string
	HostLabel    string
	ProjectRoot  string
	AgentSafe    bool
	ConsumerName string
	ExpiresAt    time.Time
	LastSeenAt   time.Time
}

type SessionView struct {
	ID           string    `json:"id"`
	LocalUser    string    `json:"local_user"`
	HostLabel    string    `json:"host_label"`
	ProjectRoot  string    `json:"project_root"`
	AgentSafe    bool      `json:"agent_safe,omitempty"`
	ConsumerName string    `json:"consumer_name,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
}

// processBinding pairs a session token with the per-process identity token
// captured at registration time. ResolveProcess re-probes the identity to
// detect pid reuse: a registered pid whose identity has changed must not
// inherit the prior session.
type processBinding struct {
	token    string
	identity string
}

type SessionStore struct {
	mu        sync.RWMutex
	sessions  map[string]Session
	processes map[int]processBinding
	now       func() time.Time
	idleTTL   time.Duration
	// processIdentity returns a stable token identifying the process at pid.
	// Set explicitly per SessionStore so tests can simulate pid reuse without
	// swapping a package-level var under a global mutex.
	processIdentity func(pid int) (string, error)
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions:        make(map[string]Session),
		processes:       make(map[int]processBinding),
		now:             func() time.Time { return time.Now().UTC() },
		idleTTL:         DefaultVaultIdleTimeout,
		processIdentity: realProcessIdentity,
	}
}

func (s *SessionStore) Open(hostLabel, projectRoot string, ttl time.Duration, agentSafe bool, consumerName string) (Session, error) {
	if ttl <= 0 {
		return Session{}, errors.New("ttl must be positive")
	}
	localUser, err := currentUser()
	if err != nil {
		return Session{}, err
	}
	now := s.now().UTC()
	session := Session{
		ID:           mustRandomHex(16),
		Token:        mustRandomHex(32),
		LocalUser:    localUser,
		HostLabel:    hostLabel,
		ProjectRoot:  CanonicalProjectRoot(projectRoot),
		AgentSafe:    agentSafe,
		ConsumerName: strings.TrimSpace(consumerName),
		ExpiresAt:    now.Add(ttl),
		LastSeenAt:   now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.Token] = session
	return session, nil
}

func (s *SessionStore) Resolve(token string) (Session, bool) {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[token]
	if !ok {
		return Session{}, false
	}
	if s.sessionExpired(session, now) {
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
	for pid, existing := range s.processes {
		if existing.token == token {
			delete(s.processes, pid)
		}
	}
	return true
}

func (s *SessionStore) RevokeAll() []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	revoked := make([]Session, 0, len(s.sessions))
	for token, session := range s.sessions {
		revoked = append(revoked, session)
		delete(s.sessions, token)
	}
	for pid := range s.processes {
		delete(s.processes, pid)
	}
	return revoked
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
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, session := range s.sessions {
		if s.sessionExpired(session, now) {
			delete(s.sessions, token)
			for pid, existing := range s.processes {
				if existing.token == token {
					delete(s.processes, pid)
				}
			}
		}
	}
}

func (s *SessionStore) RegisterProcess(sessionToken string, pid int) bool {
	if pid <= 0 {
		return false
	}
	now := s.now().UTC()
	identity, _ := s.processIdentity(pid)
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[sessionToken]
	if !ok || s.sessionExpired(session, now) {
		delete(s.sessions, sessionToken)
		return false
	}
	s.processes[pid] = processBinding{token: sessionToken, identity: identity}
	return true
}

func (s *SessionStore) ResolveProcess(pid int) (Session, string, bool) {
	lineage, err := processLineage(pid)
	if err != nil || len(lineage) == 0 {
		return Session{}, "", false
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ancestor := range lineage {
		binding, ok := s.processes[ancestor]
		if !ok {
			continue
		}
		// PID-reuse defense: re-probe the per-process identity captured at
		// registration. If both sides report a non-empty token and they
		// differ, the kernel reused this pid for an unrelated process — drop
		// the stale binding rather than honoring it. When either probe is
		// empty the platform is unsupported and we fall back to ancestry.
		if binding.identity != "" {
			current, _ := s.processIdentity(ancestor)
			if current != "" && current != binding.identity {
				delete(s.processes, ancestor)
				continue
			}
		}
		token := binding.token
		session, ok := s.sessions[token]
		if !ok || s.sessionExpired(session, now) {
			delete(s.sessions, token)
			delete(s.processes, ancestor)
			continue
		}
		session.LastSeenAt = now
		s.sessions[token] = session
		return session, token, true
	}
	return Session{}, "", false
}

func (s *SessionStore) sessionExpired(session Session, now time.Time) bool {
	if now.After(session.ExpiresAt) {
		return true
	}
	if s.idleTTL <= 0 {
		return false
	}
	return now.Sub(session.LastSeenAt) > s.idleTTL
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
	if resolved, ok := cachedEvalSymlinks(abs); ok {
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
		ID:           s.ID,
		LocalUser:    s.LocalUser,
		HostLabel:    s.HostLabel,
		ProjectRoot:  s.ProjectRoot,
		AgentSafe:    s.AgentSafe,
		ConsumerName: s.ConsumerName,
		ExpiresAt:    s.ExpiresAt,
		LastSeenAt:   s.LastSeenAt,
	}
}
