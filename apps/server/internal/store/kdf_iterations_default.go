//go:build !hasp_test_fastkdf

package store

// defaultPasswordIterations is the build-time default cost selected when the
// resolver sees an empty HASP_KDF_ITERATIONS. Production builds keep the full
// PBKDF2 cost.
const defaultPasswordIterations = productionPasswordIterations
