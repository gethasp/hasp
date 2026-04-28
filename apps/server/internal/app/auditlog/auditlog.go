// Package auditlog centralises the side-effecting helpers that wrap the
// underlying audit.Log: process-wide HMAC key state, the operator/actor
// label resolution, and the Append / AppendCLI convenience writers. The
// secret CLI surfaces (which move to internal/app/secretops/ in Stage 2d)
// and the dispatch / setup code that stays in package app both need these
// without one importing the other; auditlog is the shared seam they share.
// hasp-tpsi (Stage 2c of hasp-mgz5).
package auditlog

import (
	"os"
	"os/user"
	"strings"
	"sync"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

// Seam variables — production wires the real audit/user implementations,
// tests override these to drive specific factories or actor labels.
var (
	NewLogFn      = audit.New
	EventsFn      = (*audit.Log).Events
	CurrentUserFn = user.Current
)

var (
	currentHMACKey []byte
	keyMu          sync.RWMutex
)

// SetHMACKey installs key as the process-wide HMAC key used by Append.
// A zero-length key clears the seam so subsequent appends fall back to
// the unkeyed SHA256 chain (matches pre-unlock behaviour).
func SetHMACKey(key []byte) {
	keyMu.Lock()
	defer keyMu.Unlock()
	if len(key) == 0 {
		currentHMACKey = nil
		return
	}
	currentHMACKey = append([]byte(nil), key...)
}

// GetHMACKey returns a defensive copy of the current process-wide HMAC key,
// or nil when no key is installed.
func GetHMACKey() []byte {
	keyMu.RLock()
	defer keyMu.RUnlock()
	if len(currentHMACKey) == 0 {
		return nil
	}
	return append([]byte(nil), currentHMACKey...)
}

// ClearHMACKey removes any installed HMAC key. Equivalent to SetHMACKey(nil).
func ClearHMACKey() { SetHMACKey(nil) }

// Append writes a single event to the audit log. Construction failures and
// write failures are intentionally swallowed — callers cannot meaningfully
// recover, and the broker / CLI must not abort their primary work because
// an audit sink is unavailable.
func Append(eventType string, actor string, details map[string]any) {
	log, err := NewLogFn()
	if err != nil {
		return
	}
	log = log.WithKey(GetHMACKey())
	_, _ = log.Append(eventType, actor, details)
}

// AppendCLI is the CLI-side convenience: every operator-driven mutation /
// read records actor="user" so downstream consumers can split agent vs.
// human traffic with a simple filter.
func AppendCLI(eventType string, details map[string]any) {
	Append(eventType, "user", details)
}

// ActorLabel returns a best-effort operator label for inclusion in audit
// payload `actor_label` fields. Falls back to the USER env var, then the
// literal "unknown" so the field is never empty.
func ActorLabel() string {
	if current, err := CurrentUserFn(); err == nil {
		if strings.TrimSpace(current.Username) != "" {
			return current.Username
		}
	}
	if value := strings.TrimSpace(os.Getenv("USER")); value != "" {
		return value
	}
	return "unknown"
}
