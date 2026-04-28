package store

import (
	"fmt"
	"strconv"
	"strings"
)

// resolvePasswordIterations decides the PBKDF2 iteration count for new vaults.
// It exists as a pure function so that the policy is decoupled from process
// state (os.Args, build tags, env reads) and can be exercised directly by
// unit tests.
//
// envValue is the raw HASP_KDF_ITERATIONS reading (possibly empty / padded).
// base is the build-time default (production cost in normal builds, a much
// lower cost under the hasp_test_fastkdf build tag).
// minimum is the floor that any operator-supplied override must meet.
//
// Behaviour:
//   - empty / whitespace envValue -> return base (no override).
//   - non-numeric envValue        -> panic with a message that names the bad
//     value and the minimum, so misconfiguration is loud at startup rather
//     than silently weakening the vault.
//   - numeric below minimum       -> panic with the same shape of message.
//   - numeric at or above minimum -> return that value.
//
// The function never silently downgrades the iteration count based on the
// binary's name, which was the previous (and dangerous) seam.
func resolvePasswordIterations(envValue string, base int, minimum int) int {
	trimmed := strings.TrimSpace(envValue)
	if trimmed == "" {
		return base
	}
	parsed, err := strconv.Atoi(trimmed)
	if err != nil {
		panic(fmt.Sprintf("HASP_KDF_ITERATIONS=%q is not a valid integer; minimum is %d", trimmed, minimum))
	}
	if parsed < minimum {
		panic(fmt.Sprintf("HASP_KDF_ITERATIONS=%d is below the allowed minimum of %d", parsed, minimum))
	}
	return parsed
}
