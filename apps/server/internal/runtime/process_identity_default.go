//go:build !linux && !darwin

package runtime

// realProcessIdentity returns "" on platforms where we have not implemented
// a stable per-process token. Callers fall back to ancestry-only resolution.
func realProcessIdentity(pid int) (string, error) {
	return "", nil
}
