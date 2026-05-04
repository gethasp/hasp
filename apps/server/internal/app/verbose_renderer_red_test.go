package app

// hasp-pjh4: --verbose must reach the list renderers. Today the list
// outputs collapse useful fields ("(created at …)" is hidden, exposure
// project paths are ~-shortened, the session table omits the local
// user). When the operator passes --verbose, the renderers should
// surface those extra columns / muted details so they don't have to
// resort to --json just to see who owns a session or where exactly an
// exposure points.

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/ui"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestSecretListVerboseSurfacesCreatedAtAndAbsoluteExposurePath(t *testing.T) {
	secrets := []secretMetadataView{{
		Name:           "API_TOKEN",
		NamedReference: "@api_token",
		Kind:           store.ItemKindKV,
		CreatedAt:      "2025-01-02T03:04:05Z",
		UpdatedAt:      "2026-04-27T10:11:12Z",
		Exposures: []store.ItemExposure{{
			ProjectRoot: "/Users/test/very/deep/abs/path/to/repo",
			Reference:   "@api_token",
		}},
	}}

	var quiet bytes.Buffer
	if err := renderSecretListWithColor(&quiet, secrets, ui.ColorOptions{}); err != nil {
		t.Fatalf("non-verbose render: %v", err)
	}
	if strings.Contains(stripANSI(quiet.String()), "created 2025-01-02T03:04:05Z") {
		t.Fatalf("non-verbose render must NOT show created timestamp; got:\n%s", quiet.String())
	}

	var verbose bytes.Buffer
	if err := renderSecretListWithColor(&verbose, secrets, ui.ColorOptions{Verbose: true}); err != nil {
		t.Fatalf("verbose render: %v", err)
	}
	got := stripANSI(verbose.String())
	if !strings.Contains(got, "created 2025-01-02T03:04:05Z") {
		t.Fatalf("verbose render must show created timestamp; got:\n%s", got)
	}
	// Verbose must show the full absolute path, not the ~-shortened one.
	if !strings.Contains(got, "/Users/test/very/deep/abs/path/to/repo") {
		t.Fatalf("verbose render must show absolute exposure path; got:\n%s", got)
	}
}

func TestSessionListVerboseSurfacesLocalUserColumn(t *testing.T) {
	sessions := []runtime.SessionView{{
		ID:          "sess-abc",
		LocalUser:   "tester",
		HostLabel:   "local-cli",
		ProjectRoot: "/repo",
		AgentSafe:   true,
		ExpiresAt:   time.Now().Add(15 * time.Minute),
		LastSeenAt:  time.Now(),
	}}

	var quiet bytes.Buffer
	if err := renderSessionListWithColor(&quiet, sessions, ui.ColorOptions{}); err != nil {
		t.Fatalf("non-verbose: %v", err)
	}
	header := strings.SplitN(stripANSI(quiet.String()), "\n", 2)[0]
	if strings.Contains(strings.ToUpper(header), "USER") {
		t.Fatalf("non-verbose session list must NOT include a USER column; header=%q", header)
	}

	var verbose bytes.Buffer
	if err := renderSessionListWithColor(&verbose, sessions, ui.ColorOptions{Verbose: true}); err != nil {
		t.Fatalf("verbose: %v", err)
	}
	got := stripANSI(verbose.String())
	if !strings.Contains(strings.ToUpper(got), "USER") {
		t.Fatalf("verbose session list must include a USER column; got:\n%s", got)
	}
	if !strings.Contains(got, "tester") {
		t.Fatalf("verbose session list must include the LocalUser value; got:\n%s", got)
	}
}

func TestDebugLogSeamDefaultsToNoOpButCanBeReplaced(t *testing.T) {
	// Default seam must be a no-op: zero allocation, never writes anywhere.
	// We can't directly check "does nothing", but we can confirm calling it
	// with arbitrary input doesn't panic and that the seam is overridable
	// for tests / for the dispatcher to wire up when --debug is set.
	defer func(orig func(string, ...any)) { debugLogFn = orig }(debugLogFn)

	debugLogFn("default seam call must not panic %d", 1)

	var captured []string
	debugLogFn = func(format string, args ...any) {
		captured = append(captured, format)
	}
	debugLogFn("custom-replaced %s", "ok")
	if len(captured) != 1 || captured[0] != "custom-replaced %s" {
		t.Fatalf("debugLogFn must be a replaceable seam; captured=%v", captured)
	}
}
