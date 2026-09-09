//go:build !darwin && !linux

package runner

// Other platforms retain age-based orphan cleanup.
func tryLockRunDir(string) (func(), error) { return func() {}, nil }
