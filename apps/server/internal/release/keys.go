// Package release verifies signed binary upgrades for `hasp upgrade`.
//
// Trust model — strict pin with signed transition statements, no TOFU:
//
//  1. The binary embeds a fixed set of Ed25519 public keys (pinnedPublicKeys).
//  2. Each release ships a KEYS file listing currently-trusted keys; the
//     KEYS file itself is signed by at least one key in the embedded pin set.
//  3. The release tarball is signed by some key listed in the KEYS file.
//  4. Verification fails closed if either signature does not chain back
//     to an embedded key. There is no auto-fetch, no first-use trust.
//
// Rotation: an old key cosigns a KEYS file that lists the new key. A
// release built after rotation can be signed by either the old or new
// key — the old binary trusts the KEYS file (signed by old key), then
// trusts whatever key in that KEYS file signed the tarball.
package release

import (
	"encoding/hex"
	"strings"
)

// pinnedKeysHex is populated at link time via:
//
//	go build -ldflags "-X github.com/gethasp/hasp/apps/server/internal/release.pinnedKeysHex=<hex1>,<hex2>"
//
// Each entry is a 64-hex-char Ed25519 public key. Multiple keys are
// comma-separated to support overlap during rotation.
//
// An empty pin set disables `hasp upgrade` (the command refuses to
// run). This is intentional: an unsigned `go build` cannot be used
// to upgrade itself.
var pinnedKeysHex = ""

// PinnedPublicKeys returns the set of embedded trust roots. The
// returned slice is a fresh copy; callers may mutate it freely.
func PinnedPublicKeys() [][]byte {
	if strings.TrimSpace(pinnedKeysHex) == "" {
		return nil
	}
	parts := strings.Split(pinnedKeysHex, ",")
	out := make([][]byte, 0, len(parts))
	for _, part := range parts {
		hexStr := strings.TrimSpace(part)
		if hexStr == "" {
			continue
		}
		raw, err := hex.DecodeString(hexStr)
		if err != nil || len(raw) != 32 {
			// A malformed pinned key is a build-time bug; skip it.
			// Verification will fail closed if no valid pin remains.
			continue
		}
		out = append(out, raw)
	}
	return out
}

// SetPinnedKeysForTest replaces the pinned key set for the duration
// of a test. It returns a restore function.
func SetPinnedKeysForTest(hexCSV string) func() {
	prev := pinnedKeysHex
	pinnedKeysHex = hexCSV
	return func() { pinnedKeysHex = prev }
}
