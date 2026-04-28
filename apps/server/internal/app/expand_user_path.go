package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// expandUserPath expands a leading "~" to the current user's home directory.
// "~user/..." forms are rejected with an explicit error. All other paths
// (absolute, relative, or empty) are returned unchanged.
func expandUserPath(in string) (string, error) {
	if in == "" {
		return "", nil
	}
	if !strings.HasPrefix(in, "~") {
		return in, nil
	}
	// Reject ~user/... forms.
	rest := in[1:] // everything after the leading ~
	if rest != "" && !strings.HasPrefix(rest, "/") {
		return "", fmt.Errorf("~user expansion not supported (got %q); use an absolute path or $HOME instead", in)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expandUserPath: could not determine home directory: %w", err)
	}
	if rest == "" {
		return home, nil
	}
	// rest starts with "/", e.g. "/foo" → join home + "foo"
	return filepath.Join(home, rest[1:]), nil
}
