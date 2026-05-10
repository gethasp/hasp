package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

type VerifyReport struct {
	OK                bool
	TotalEntries      int
	FirstCorruptionAt *int64
	Err               error
}

var resolveAuditPaths = paths.Resolve

const (
	EventRead       = "read"
	EventRun        = "run"
	EventInjectSafe = "inject_safe"
	EventWriteEnv   = "write_env"
	EventCapture    = "capture"
	EventApprove    = "approve"
	EventDeny       = "deny"
	EventRedact     = "redact"
	EventOverride   = "override"
	EventRepoBlock  = "repo_block"
	EventInit       = "init"
	EventImport     = "import"
	EventRekdf      = "rekdf"
	EventRekey      = "rekey"
)

// SchemeSHA256 is the legacy unkeyed scheme — present in events written
// before the audit key was wired in. SchemeHMACSHA256V1 is the keyed
// scheme written when an HMAC key has been installed via WithKey. Verify
// validates each event under the scheme it declared, so a single chain
// can mix legacy and keyed lines (the upgrade path).
const (
	SchemeSHA256       = "sha256"
	SchemeHMACSHA256V1 = "hmac-sha256-v1"
)

type Event struct {
	Sequence  int64          `json:"sequence"`
	Timestamp time.Time      `json:"timestamp"`
	Type      string         `json:"type"`
	Actor     string         `json:"actor,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
	PrevHash  string         `json:"prev_hash"`
	Hash      string         `json:"hash"`
	Scheme    string         `json:"scheme,omitempty"`
}

type Log struct {
	mu          sync.Mutex
	path        string
	now         func() time.Time
	key         []byte
	cachedLast  *Event
	cachedState fileState
	cacheValid  bool
}

type fileState struct {
	size        int64
	modUnixNano int64
	ctimeSec    int64
	ctimeNsec   int64
	dev         uint64
	ino         uint64
	cacheable   bool
}

type auditWriter interface {
	Write([]byte) (int, error)
	Close() error
}

var (
	auditMkdirAll  = os.MkdirAll
	auditFileState = auditFileStateFromInfo
	openAuditFile  = func(path string) (auditWriter, error) {
		return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	}
)

func New() (*Log, error) {
	resolved, err := resolveAuditPaths()
	if err != nil {
		return nil, err
	}
	return NewForPaths(resolved), nil
}

func NewForPaths(resolved paths.Paths) *Log {
	return &Log{
		path: resolved.AuditPath,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

// WithKey installs an HMAC key for subsequent Append calls. Passing nil or
// an empty slice clears the key — Append then falls back to plain SHA-256
// (the SchemeSHA256 path) for callers that have no vault open. Returns
// the receiver so callers can chain `audit.New().WithKey(k)`.
func (l *Log) WithKey(key []byte) *Log {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(key) == 0 {
		l.key = nil
	} else {
		l.key = append([]byte(nil), key...)
	}
	return l
}

func (l *Log) Append(eventType string, actor string, details map[string]any) (Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	last, sequence, err := l.readLastLocked()
	if err != nil {
		return Event{}, err
	}
	event := Event{
		Sequence:  sequence + 1,
		Timestamp: l.now(),
		Type:      eventType,
		Actor:     actor,
		Details:   details,
	}
	if last != nil {
		event.PrevHash = last.Hash
	}
	event.Scheme, event.Hash = hashEvent(event, l.key)

	if err := auditMkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return Event{}, fmt.Errorf("create audit dir: %w", err)
	}
	file, err := openAuditFile(l.path)
	if err != nil {
		return Event{}, fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	payload, err := json.Marshal(event)
	if err != nil {
		return Event{}, fmt.Errorf("encode audit event: %w", err)
	}
	if _, err := file.Write(append(payload, '\n')); err != nil {
		return Event{}, fmt.Errorf("append audit event: %w", err)
	}
	l.cacheEvent(event)
	return event, nil
}

func (l *Log) Verify() error {
	report, err := l.VerifyDetailed()
	if err != nil {
		return err
	}
	if !report.OK {
		return report.Err
	}
	return nil
}

func (l *Log) VerifyDetailed() (VerifyReport, error) {
	file, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return VerifyReport{OK: true}, nil
		}
		return VerifyReport{}, fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var previous string
	var sequence int64
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			first := sequence + 1
			return VerifyReport{OK: false, TotalEntries: int(sequence), FirstCorruptionAt: &first, Err: fmt.Errorf("decode audit event: %w", err)}, nil
		}
		sequence++
		if event.Sequence != sequence {
			first := sequence
			return VerifyReport{OK: false, TotalEntries: int(sequence), FirstCorruptionAt: &first, Err: fmt.Errorf("audit sequence mismatch at %d", event.Sequence)}, nil
		}
		if event.PrevHash != previous {
			first := event.Sequence
			return VerifyReport{OK: false, TotalEntries: int(sequence), FirstCorruptionAt: &first, Err: fmt.Errorf("audit chain mismatch at %d", event.Sequence)}, nil
		}
		key, err := l.keyForScheme(event.Scheme)
		if err != nil {
			first := event.Sequence
			return VerifyReport{OK: false, TotalEntries: int(sequence), FirstCorruptionAt: &first, Err: fmt.Errorf("audit scheme at %d: %w", event.Sequence, err)}, nil
		}
		_, expected := hashEvent(Event{
			Sequence:  event.Sequence,
			Timestamp: event.Timestamp,
			Type:      event.Type,
			Actor:     event.Actor,
			Details:   event.Details,
			PrevHash:  event.PrevHash,
		}, key)
		if event.Hash != expected {
			first := event.Sequence
			return VerifyReport{OK: false, TotalEntries: int(sequence), FirstCorruptionAt: &first, Err: fmt.Errorf("audit hash mismatch at %d", event.Sequence)}, nil
		}
		previous = event.Hash
	}
	if err := scanner.Err(); err != nil {
		return VerifyReport{}, fmt.Errorf("scan audit log: %w", err)
	}
	return VerifyReport{OK: true, TotalEntries: int(sequence)}, nil
}

func (l *Log) Events() ([]Event, error) {
	file, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	events := []Event{}
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("decode audit event: %w", err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan audit log: %w", err)
	}
	return events, nil
}

func (l *Log) HMACKey() []byte {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.key...)
}

func (l *Log) Checkpoint() (int64, string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	last, sequence, err := l.readLastLocked()
	if err != nil {
		return 0, "", err
	}
	if last == nil {
		return 0, "", nil
	}
	return sequence, last.Hash, nil
}

func (l *Log) readLastLocked() (*Event, int64, error) {
	stat, err := os.Stat(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			l.clearCache()
			return nil, 0, nil
		}
		return nil, 0, fmt.Errorf("stat audit log: %w", err)
	}
	state := auditFileState(stat)
	if state.cacheable && l.cacheValid && l.cachedLast != nil && l.cachedState == state {
		cached := *l.cachedLast
		return &cached, cached.Sequence, nil
	}

	file, err := os.Open(l.path)
	if err != nil {
		return nil, 0, fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var last *Event
	var count int64
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, 0, fmt.Errorf("decode audit event: %w", err)
		}
		value := event
		last = &value
		count++
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("scan audit log: %w", err)
	}
	if last == nil {
		l.clearCache()
		return nil, 0, nil
	}
	if !state.cacheable {
		l.clearCache()
		return last, count, nil
	}
	cached := *last
	l.cachedLast = &cached
	l.cachedState = state
	l.cacheValid = true
	return last, count, nil
}

func (l *Log) cacheEvent(event Event) {
	stat, err := os.Stat(l.path)
	if err != nil {
		l.clearCache()
		return
	}
	state := auditFileState(stat)
	if !state.cacheable {
		l.clearCache()
		return
	}
	cached := event
	l.cachedLast = &cached
	l.cachedState = state
	l.cacheValid = true
}

func (l *Log) clearCache() {
	l.cachedLast = nil
	l.cachedState = fileState{}
	l.cacheValid = false
}

// keyForScheme picks the right key for verifying an event under its
// declared scheme. SchemeSHA256 (or empty, for legacy events) returns
// nil — hashEvent treats nil as the unkeyed branch. SchemeHMACSHA256V1
// requires a key on the Log; otherwise verification can't even start
// and we surface that fail-closed instead of silently passing.
func (l *Log) keyForScheme(scheme string) ([]byte, error) {
	switch scheme {
	case "", SchemeSHA256:
		return nil, nil
	case SchemeHMACSHA256V1:
		if len(l.key) == 0 {
			return nil, fmt.Errorf("hmac key not installed for scheme %q", scheme)
		}
		return l.key, nil
	default:
		return nil, fmt.Errorf("unknown audit scheme %q", scheme)
	}
}

// hashEvent canonicalises an event and returns (scheme, hex-digest).
// With no key, falls back to plain SHA-256 — preserves the legacy chain
// shape so an upgraded daemon can keep appending without rewriting
// history. With a key, switches to HMAC-SHA256 and stamps the event with
// SchemeHMACSHA256V1 so Verify knows which branch to take.
func hashEvent(event Event, key []byte) (string, string) {
	payload := struct {
		Sequence  int64          `json:"sequence"`
		Timestamp time.Time      `json:"timestamp"`
		Type      string         `json:"type"`
		Actor     string         `json:"actor,omitempty"`
		Details   map[string]any `json:"details,omitempty"`
		PrevHash  string         `json:"prev_hash"`
	}{
		Sequence:  event.Sequence,
		Timestamp: event.Timestamp,
		Type:      event.Type,
		Actor:     event.Actor,
		Details:   event.Details,
		PrevHash:  event.PrevHash,
	}
	data, _ := json.Marshal(payload)
	if len(key) == 0 {
		sum := sha256.Sum256(data)
		return SchemeSHA256, hex.EncodeToString(sum[:])
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return SchemeHMACSHA256V1, hex.EncodeToString(mac.Sum(nil))
}
