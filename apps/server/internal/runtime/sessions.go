package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/gitsafe"
	"github.com/gethasp/hasp/apps/server/internal/leases"
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
	ID            string
	Token         string
	LocalUser     string
	HostLabel     string
	ProjectRoot   string
	AgentSafe     bool
	ConsumerName  string
	Internal      bool
	OpenedAt      time.Time
	ExpiresAt     time.Time
	LastSeenAt    time.Time
	RevokedAt     *time.Time
	LeaseStatus   string
	LeaseSecretID string
	LeaseScope    string
}

type SessionView struct {
	ID           string    `json:"id"`
	LocalUser    string    `json:"local_user"`
	HostLabel    string    `json:"host_label"`
	ProjectRoot  string    `json:"project_root"`
	AgentSafe    bool      `json:"agent_safe,omitempty"`
	ConsumerName string    `json:"consumer_name,omitempty"`
	Internal     bool      `json:"internal,omitempty"`
	OpenedAt     time.Time `json:"opened_at"`
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
	mu                            sync.RWMutex
	sessions                      map[string]Session
	processes                     map[int]processBinding
	locked                        bool
	now                           func() time.Time
	idleTTL                       time.Duration
	processIdentityDegraded       bool
	processIdentityDegradedReason string
	// processIdentity returns a stable token identifying the process at pid.
	// Set explicitly per SessionStore so tests can simulate pid reuse without
	// swapping a package-level var under a global mutex.
	processIdentity func(pid int) (string, error)
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions:        make(map[string]Session),
		processes:       make(map[int]processBinding),
		locked:          true,
		now:             func() time.Time { return time.Now().UTC() },
		idleTTL:         DefaultVaultIdleTimeout,
		processIdentity: realProcessIdentity,
	}
}

func (s *SessionStore) Open(hostLabel, projectRoot string, ttl time.Duration, agentSafe bool, consumerName string) (Session, error) {
	return s.open(hostLabel, projectRoot, ttl, agentSafe, consumerName, false)
}

func (s *SessionStore) OpenInternal(hostLabel, projectRoot string, ttl time.Duration, agentSafe bool, consumerName string) (Session, error) {
	return s.open(hostLabel, projectRoot, ttl, agentSafe, consumerName, true)
}

func (s *SessionStore) open(hostLabel, projectRoot string, ttl time.Duration, agentSafe bool, consumerName string, internal bool) (Session, error) {
	session, err := s.newSession(hostLabel, projectRoot, ttl, agentSafe, consumerName)
	if err != nil {
		return Session{}, err
	}
	session.Internal = internal
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.Token] = session
	s.locked = false
	return session, nil
}

func (s *SessionStore) newSession(hostLabel, projectRoot string, ttl time.Duration, agentSafe bool, consumerName string) (Session, error) {
	if ttl <= 0 {
		return Session{}, errors.New("ttl must be positive")
	}
	localUser, err := currentUser()
	if err != nil {
		return Session{}, err
	}
	now := s.now().UTC()
	id, err := randomHex(16)
	if err != nil {
		return Session{}, fmt.Errorf("generate session id: %w", err)
	}
	token, err := randomHex(32)
	if err != nil {
		return Session{}, fmt.Errorf("generate session token: %w", err)
	}
	return Session{
		ID:           id,
		Token:        token,
		LocalUser:    localUser,
		HostLabel:    hostLabel,
		ProjectRoot:  CanonicalProjectRoot(projectRoot),
		AgentSafe:    agentSafe,
		ConsumerName: strings.TrimSpace(consumerName),
		OpenedAt:     now,
		ExpiresAt:    now.Add(ttl),
		LastSeenAt:   now,
	}, nil
}

func (s *SessionStore) OpenLease(hostLabel, secretID, scope string, ttl time.Duration, consumerName string) (Session, error) {
	session, err := s.newSession(hostLabel, "", ttl, false, consumerName)
	if err != nil {
		return Session{}, err
	}
	session.LeaseSecretID = strings.TrimSpace(secretID)
	session.LeaseScope = strings.TrimSpace(scope)
	if session.LeaseScope == "" {
		session.LeaseScope = "session"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.Token] = session
	s.locked = false
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
	if session.RevokedAt != nil {
		return Session{}, false
	}
	if s.sessionExpired(session, now) {
		s.markExpiredLocked(token, session, now)
		return Session{}, false
	}
	session.LastSeenAt = now
	s.sessions[token] = session
	return session, true
}

func (s *SessionStore) Revoke(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[token]
	if !ok || session.RevokedAt != nil {
		return false
	}
	now := s.now().UTC()
	session.RevokedAt = &now
	session.LeaseStatus = "revoked"
	s.sessions[token] = session
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
	now := s.now().UTC()
	revoked := make([]Session, 0, len(s.sessions))
	for token, session := range s.sessions {
		if session.RevokedAt != nil || s.sessionExpired(session, now) {
			if session.RevokedAt == nil && s.sessionExpired(session, now) {
				s.markExpiredLocked(token, session, now)
			}
			continue
		}
		session.RevokedAt = &now
		session.LeaseStatus = "revoked"
		s.sessions[token] = session
		revoked = append(revoked, session)
	}
	for pid := range s.processes {
		delete(s.processes, pid)
	}
	s.locked = true
	return revoked
}

func (s *SessionStore) IsLocked() bool {
	s.PruneExpired()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.locked || s.activeCountLocked(s.now().UTC()) == 0
}

func (s *SessionStore) activeCountLocked(now time.Time) int {
	count := 0
	for _, session := range s.sessions {
		if session.RevokedAt == nil && !s.sessionExpired(session, now) {
			count++
		}
	}
	return count
}

func (s *SessionStore) ActiveCount() int {
	s.PruneExpired()
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	now := s.now().UTC()
	for _, session := range s.sessions {
		if session.RevokedAt == nil && !s.sessionExpired(session, now) {
			count++
		}
	}
	return count
}

func (s *SessionStore) Snapshot() []Session {
	s.PruneExpired()
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		if session.RevokedAt == nil && !s.sessionExpired(session, s.now().UTC()) {
			out = append(out, session)
		}
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

func (s *SessionStore) VisibleSnapshot() []Session {
	sessions := s.Snapshot()
	out := make([]Session, 0, len(sessions))
	for _, session := range sessions {
		if session.Internal {
			continue
		}
		out = append(out, session)
	}
	return out
}

func (s *SessionStore) PruneExpired() {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, session := range s.sessions {
		if s.sessionExpired(session, now) {
			s.markExpiredLocked(token, session, now)
			for pid, existing := range s.processes {
				if existing.token == token {
					delete(s.processes, pid)
				}
			}
		}
	}
	if s.activeCountLocked(now) == 0 {
		s.locked = true
	}
}

func (s *SessionStore) RegisterProcess(sessionToken string, pid int) bool {
	if pid <= 0 {
		return false
	}
	now := s.now().UTC()
	identity, identityErr := s.processIdentity(pid)
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[sessionToken]
	if !ok || session.RevokedAt != nil || s.sessionExpired(session, now) {
		if ok && session.RevokedAt == nil && s.sessionExpired(session, now) {
			s.markExpiredLocked(sessionToken, session, now)
		}
		return false
	}
	if identityErr != nil {
		s.markProcessIdentityDegradedLocked("identity probe failed: " + identityErr.Error())
	} else if identity == "" {
		s.markProcessIdentityDegradedLocked("identity probe unavailable")
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
			current, err := s.processIdentity(ancestor)
			if err != nil {
				s.markProcessIdentityDegradedLocked("identity recheck failed: " + err.Error())
			} else if current == "" {
				s.markProcessIdentityDegradedLocked("identity recheck unavailable")
			}
			if current != "" && current != binding.identity {
				delete(s.processes, ancestor)
				continue
			}
		}
		token := binding.token
		session, ok := s.sessions[token]
		if !ok || session.RevokedAt != nil || s.sessionExpired(session, now) {
			if ok && session.RevokedAt == nil && s.sessionExpired(session, now) {
				s.markExpiredLocked(token, session, now)
			}
			delete(s.processes, ancestor)
			continue
		}
		session.LastSeenAt = now
		s.sessions[token] = session
		return session, token, true
	}
	return Session{}, "", false
}

func (s *SessionStore) ProcessIdentityDegraded() (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.processIdentityDegraded, s.processIdentityDegradedReason
}

func (s *SessionStore) markProcessIdentityDegradedLocked(reason string) {
	s.processIdentityDegraded = true
	if s.processIdentityDegradedReason == "" {
		s.processIdentityDegradedReason = reason
	}
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

func (s *SessionStore) markExpiredLocked(token string, session Session, now time.Time) {
	if session.RevokedAt == nil {
		session.RevokedAt = &now
		session.LeaseStatus = "expired"
		s.sessions[token] = session
	}
}

func (s *SessionStore) RevokeLeaseID(id string) (Session, bool, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Session{}, false, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	for token, session := range s.sessions {
		if session.ID != id {
			continue
		}
		if session.RevokedAt != nil {
			return session, true, false
		}
		if s.sessionExpired(session, now) {
			s.markExpiredLocked(token, session, now)
			return session, true, false
		}
		session.RevokedAt = &now
		session.LeaseStatus = "revoked"
		s.sessions[token] = session
		for pid, existing := range s.processes {
			if existing.token == token {
				delete(s.processes, pid)
			}
		}
		return session, true, true
	}
	return Session{}, false, false
}

func (s *SessionStore) RevokeAllForConsumer(consumerID string) []Session {
	consumerID = strings.TrimSpace(consumerID)
	if consumerID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	revoked := make([]Session, 0)
	for token, session := range s.sessions {
		if session.RevokedAt != nil || s.sessionExpired(session, now) {
			if session.RevokedAt == nil && s.sessionExpired(session, now) {
				s.markExpiredLocked(token, session, now)
			}
			continue
		}
		if sessionConsumerID(session) != consumerID {
			continue
		}
		session.RevokedAt = &now
		session.LeaseStatus = "revoked"
		s.sessions[token] = session
		revoked = append(revoked, session)
		for pid, existing := range s.processes {
			if existing.token == token {
				delete(s.processes, pid)
			}
		}
	}
	return revoked
}

func (s *SessionStore) LeaseSnapshot() []leases.Lease {
	s.PruneExpired()
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now().UTC()
	out := make([]leases.Lease, 0, len(s.sessions))
	for _, session := range s.sessions {
		if session.Internal {
			continue
		}
		status := "active"
		if session.RevokedAt != nil {
			status = session.LeaseStatus
			if status == "" {
				status = "revoked"
			}
		} else if s.sessionExpired(session, now) {
			status = "expired"
		}
		out = append(out, leases.Lease{
			ID:         session.ID,
			SecretID:   sessionSecretID(session),
			ConsumerID: sessionConsumerID(session),
			GrantedAt:  session.OpenedAt,
			ExpiresAt:  session.ExpiresAt,
			LastUsedAt: session.LastSeenAt,
			Scope:      sessionScope(session),
			Status:     status,
		})
	}
	return out
}

func sessionConsumerID(session Session) string {
	if strings.TrimSpace(session.ConsumerName) != "" {
		return strings.TrimSpace(session.ConsumerName)
	}
	if strings.TrimSpace(session.HostLabel) != "" {
		return strings.TrimSpace(session.HostLabel)
	}
	return strings.TrimSpace(session.LocalUser)
}

func sessionSecretID(session Session) string {
	if strings.TrimSpace(session.LeaseSecretID) != "" {
		return strings.TrimSpace(session.LeaseSecretID)
	}
	if strings.TrimSpace(session.ProjectRoot) != "" {
		return strings.TrimSpace(session.ProjectRoot)
	}
	return "session:" + session.ID
}

func sessionScope(session Session) string {
	if strings.TrimSpace(session.LeaseScope) != "" {
		return strings.TrimSpace(session.LeaseScope)
	}
	if strings.TrimSpace(session.ProjectRoot) != "" {
		return "project"
	}
	return "session"
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := randomRead(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
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
		Internal:     s.Internal,
		OpenedAt:     s.OpenedAt,
		ExpiresAt:    s.ExpiresAt,
		LastSeenAt:   s.LastSeenAt,
	}
}
