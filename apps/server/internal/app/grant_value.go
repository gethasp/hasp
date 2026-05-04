package app

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// errGrantWindowConflict signals that the caller passed a duration-shaped
// grant value (e.g. --grant-secret 15m) alongside an explicit --grant-window
// value. Both cannot bind the window at once; the user must drop one.
var errGrantWindowConflict = errors.New("--grant-window conflicts with the duration value already on --grant-* (drop one)")

// parseGrantValue interprets a --grant-* flag value with shape dispatch:
//
//	""            → ("", 0, nil)            no grant requested
//	"once"        → (GrantOnce, 0, nil)
//	"session"     → (GrantSession, 0, nil)
//	"window"      → (GrantWindow, 0, nil)   legacy bareword (needs --grant-window)
//	"<duration>"  → (GrantWindow, d, nil)   any positive Go duration string
//
// Anything else returns an error. Whitespace is tolerated so callers can keep
// their CLI parsing uniform with the rest of the flag surface.
func parseGrantValue(raw string) (store.GrantScope, time.Duration, error) {
	value := strings.TrimSpace(raw)
	switch value {
	case "":
		return "", 0, nil
	case string(store.GrantOnce):
		return store.GrantOnce, 0, nil
	case string(store.GrantSession):
		return store.GrantSession, 0, nil
	case string(store.GrantWindow):
		return store.GrantWindow, 0, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return "", 0, fmt.Errorf("unrecognized grant value %q: expected once|session|window|<duration>", raw)
	}
	if d <= 0 {
		return "", 0, fmt.Errorf("grant duration %q must be positive", raw)
	}
	return store.GrantWindow, d, nil
}

// resolveGrant blends the new shape-dispatched value with the legacy
// --grant-window fallback. Only the bareword "window" consumes the fallback;
// duration-shaped values must not be silently overridden by --grant-window
// because that recreates the very ambiguity hasp-fbw9 closes.
func resolveGrant(value string, fallback time.Duration) (store.GrantScope, time.Duration, error) {
	scope, ttl, err := parseGrantValue(value)
	if err != nil {
		return "", 0, err
	}
	if scope == store.GrantWindow && ttl > 0 && fallback > 0 {
		return "", 0, errGrantWindowConflict
	}
	if scope == store.GrantWindow && ttl == 0 {
		return store.GrantWindow, fallback, nil
	}
	return scope, ttl, nil
}

// pickGrantWindow merges per-flag window TTLs into the single shared duration
// the broker accepts. Zero values mean "this flag did not pin a duration".
// Conflicting non-zero values produce a precise error so the user can drop
// one rather than having the daemon silently pick a winner.
func pickGrantWindow(durations ...time.Duration) (time.Duration, error) {
	var effective time.Duration
	for _, d := range durations {
		if d == 0 {
			continue
		}
		if effective > 0 && effective != d {
			return 0, fmt.Errorf("grant durations conflict: %s vs %s (drop one)", effective, d)
		}
		effective = d
	}
	return effective, nil
}
