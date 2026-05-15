//go:build !linux && !darwin

package runtime

// realProcessIdentity returns "" on platforms where we have not implemented
// a stale-binding token. Callers must fail closed for implicit process binding
// on these platforms.
func realProcessIdentity(pid int) (string, error) {
	return "", nil
}
