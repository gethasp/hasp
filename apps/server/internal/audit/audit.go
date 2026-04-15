package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

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
)

type Event struct {
	Sequence  int64          `json:"sequence"`
	Timestamp time.Time      `json:"timestamp"`
	Type      string         `json:"type"`
	Actor     string         `json:"actor,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
	PrevHash  string         `json:"prev_hash"`
	Hash      string         `json:"hash"`
}

type Log struct {
	path string
	now  func() time.Time
}

type auditWriter interface {
	Write([]byte) (int, error)
	Close() error
}

var (
	auditMkdirAll = os.MkdirAll
	openAuditFile = func(path string) (auditWriter, error) {
		return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	}
)

func New() (*Log, error) {
	resolved, err := resolveAuditPaths()
	if err != nil {
		return nil, err
	}
	return &Log{
		path: resolved.AuditPath,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}, nil
}

func (l *Log) Append(eventType string, actor string, details map[string]any) (Event, error) {
	last, sequence, err := l.readLast()
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
	event.Hash = hashEvent(event)

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
	return event, nil
}

func (l *Log) Verify() error {
	file, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var previous string
	var sequence int64
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return fmt.Errorf("decode audit event: %w", err)
		}
		sequence++
		if event.Sequence != sequence {
			return fmt.Errorf("audit sequence mismatch at %d", event.Sequence)
		}
		if event.PrevHash != previous {
			return fmt.Errorf("audit chain mismatch at %d", event.Sequence)
		}
		expected := hashEvent(Event{
			Sequence:  event.Sequence,
			Timestamp: event.Timestamp,
			Type:      event.Type,
			Actor:     event.Actor,
			Details:   event.Details,
			PrevHash:  event.PrevHash,
		})
		if event.Hash != expected {
			return fmt.Errorf("audit hash mismatch at %d", event.Sequence)
		}
		previous = event.Hash
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan audit log: %w", err)
	}
	return nil
}

func (l *Log) Checkpoint() (int64, string, error) {
	last, sequence, err := l.readLast()
	if err != nil {
		return 0, "", err
	}
	if last == nil {
		return 0, "", nil
	}
	return sequence, last.Hash, nil
}

func (l *Log) readLast() (*Event, int64, error) {
	file, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
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
	return last, count, nil
}

func hashEvent(event Event) string {
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
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
