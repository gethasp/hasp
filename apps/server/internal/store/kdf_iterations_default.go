//go:build !hasp_test_fastkdf

package store

// defaultPasswordIterations is the build-time default cost selected when the
// resolver sees an empty HASP_KDF_ITERATIONS. Production builds keep the full
// PBKDF2 cost.
const defaultPasswordIterations = productionPasswordIterations

// minPasswordIterations is the floor the resolver enforces on operator
// overrides. Set high enough in production builds that an env override cannot
// silently weaken the KDF below current OWASP/NIST guidance.
const minPasswordIterations = 300_000
