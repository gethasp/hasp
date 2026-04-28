//go:build !hasp_test_fastkdf

package store

// argon2id tuning parameters for production builds. Values follow RFC 9106
// guidance for an interactive use-case: t=3, m=64MiB, p=1. Memory is in KiB.
const (
	passwordArgon2Time        uint32 = 3
	passwordArgon2MemoryKiB   uint32 = 64 * 1024
	passwordArgon2Parallelism uint8  = 1
)
