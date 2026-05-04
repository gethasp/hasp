package release

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrUntrustedKEYS is returned when the KEYS file's signature does
// not validate against any embedded pinned key. The caller should
// surface a precise diagnostic — never auto-fetch a replacement.
var ErrUntrustedKEYS = errors.New("KEYS file is not signed by any embedded trust root")

// ErrUntrustedTarball is returned when the tarball signature does
// not validate against any key listed in the (already-trusted) KEYS
// file.
var ErrUntrustedTarball = errors.New("tarball is not signed by any key in the verified KEYS file")

// ErrNoPinnedKeys is returned when the binary has no embedded trust
// roots — typically an unsigned developer build.
var ErrNoPinnedKeys = errors.New("binary has no embedded release keys; upgrade disabled")

// ErrMalformedKEYS is returned for parse failures in the KEYS file
// (bad hex, wrong key length, etc.). Treated as "untrusted" by the
// caller; surfaced separately so the diagnostic can name the cause.
var ErrMalformedKEYS = errors.New("KEYS file is malformed")

// VerifyKEYS parses keysFile, validates keysSig against the embedded
// pin set, and returns the slice of currently-trusted Ed25519 public
// keys listed in the file. Empty result on error.
//
// keysFile lines: "<64-hex pubkey> [comment]". Lines starting with
// '#' and blank lines are ignored.
func VerifyKEYS(keysFile, keysSig []byte, pinned [][]byte) ([][]byte, error) {
	if len(pinned) == 0 {
		return nil, ErrNoPinnedKeys
	}
	if len(keysSig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signature must be %d bytes, got %d", ErrUntrustedKEYS, ed25519.SignatureSize, len(keysSig))
	}
	if !verifyAny(pinned, keysFile, keysSig) {
		return nil, ErrUntrustedKEYS
	}
	keys, err := parseKEYS(keysFile)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: file lists no keys", ErrMalformedKEYS)
	}
	return keys, nil
}

// VerifyTarball checks tarballSig against trustedKeys (which the
// caller obtained from VerifyKEYS). On success it returns the
// fingerprint (hex) of the signing key so callers can log which
// identity authorised the upgrade.
func VerifyTarball(tarball, tarballSig []byte, trustedKeys [][]byte) (string, error) {
	if len(tarballSig) != ed25519.SignatureSize {
		return "", fmt.Errorf("%w: signature must be %d bytes, got %d", ErrUntrustedTarball, ed25519.SignatureSize, len(tarballSig))
	}
	for _, key := range trustedKeys {
		if ed25519.Verify(ed25519.PublicKey(key), tarball, tarballSig) {
			return hex.EncodeToString(key), nil
		}
	}
	return "", ErrUntrustedTarball
}

func verifyAny(keys [][]byte, msg, sig []byte) bool {
	for _, key := range keys {
		if len(key) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(key), msg, sig) {
			return true
		}
	}
	return false
}

func parseKEYS(data []byte) ([][]byte, error) {
	out := make([][]byte, 0, 4)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 4*1024), 64*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// First whitespace-separated token is the hex key. Anything
		// after is a free-form comment for human readers.
		fields := strings.Fields(line)
		raw, err := hex.DecodeString(fields[0])
		if err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrMalformedKEYS, lineNum, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: line %d: key must be %d bytes, got %d", ErrMalformedKEYS, lineNum, ed25519.PublicKeySize, len(raw))
		}
		out = append(out, raw)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedKEYS, err)
	}
	return out, nil
}
