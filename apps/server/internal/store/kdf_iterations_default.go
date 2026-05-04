//go:build !hasp_test_fastkdf

package store

// defaultPasswordIterations is the build-time PBKDF2 compatibility cost.
// Production builds keep the full legacy cost for old vault envelopes.
const defaultPasswordIterations = productionPasswordIterations
