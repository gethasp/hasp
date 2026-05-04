//go:build darwin

package runtime

import "os"

// init ensures that t.TempDir() produces paths short enough to bind as a Unix
// socket on macOS (sun_path limit ≈ 103 chars). The default $TMPDIR on macOS
// is a long path under /var/folders/…; GOTMPDIR overrides the base used by
// testing.T.TempDir.
func init() {
	if os.Getenv("GOTMPDIR") == "" {
		_ = os.Setenv("GOTMPDIR", "/tmp")
	}
}
