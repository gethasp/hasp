// Command sign is the canonical hasp release-signing tool.
//
// Usage:
//
//	# Generate a fresh Ed25519 keypair (private key written to disk).
//	go run ./tools/release sign keygen --out ./hasp-key
//
//	# Sign a release tarball with an existing key.
//	go run ./tools/release sign tarball \
//	    --key ./hasp-key \
//	    --in dist/hasp-v0.2.0-darwin-arm64.tar.gz
//	# Produces dist/hasp-v0.2.0-darwin-arm64.tar.gz.sig (raw 64-byte Ed25519).
//
//	# Sign a KEYS file. The KEYS file lists hex-encoded Ed25519 public
//	# keys, one per line, with optional comments. The signing key here
//	# must be a key that the installed binaries pin (i.e., a current or
//	# old trust root).
//	go run ./tools/release sign keys --key ./hasp-key --in dist/KEYS-v0.2.0
//
//	# Print the public-key hex for embedding via -ldflags -X.
//	go run ./tools/release sign pubkey --key ./hasp-key
//
//	# Verify a KEYS chain and tarball signature against embedded-root hex.
//	go run ./tools/release sign verify \
//	    --roots-hex "$HASP_UPGRADE_TRUST_ROOTS_HEX" \
//	    --keys dist/KEYS-v0.2.0 \
//	    --keys-sig dist/KEYS-v0.2.0.sig \
//	    --tarball dist/hasp-v0.2.0-darwin-arm64.tar.gz \
//	    --tarball-sig dist/hasp-v0.2.0-darwin-arm64.tar.gz.sig
//
// The private key file format is the raw 64-byte Ed25519 seed+public.
// Treat it like any other signing key: keep it offline, on hardware
// where possible. Compromise of an active signing key forces a key
// rotation (publish a KEYS file signed by an unrelated trust root).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/release"
)

func main() {
	signExit(run(os.Args[1:], os.Stdout, os.Stderr))
}

var (
	signRandReader io.Reader = rand.Reader
	signReadFile             = os.ReadFile
	signWriteFile            = os.WriteFile
	signExit                 = os.Exit
)

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		return usage(stderr)
	}
	switch args[0] {
	case "keygen":
		return cmdKeygen(args[1:], stderr)
	case "tarball", "keys", "sign":
		return cmdSign(args[1:], stderr)
	case "pubkey":
		return cmdPubkey(args[1:], stdout, stderr)
	case "verify":
		return cmdVerify(args[1:], stdout, stderr)
	default:
		return usage(stderr)
	}
}

func usage(stderr io.Writer) int {
	fmt.Fprintln(stderr, "usage: sign keygen|tarball|keys|pubkey|verify [flags]")
	return 2
}

func cmdKeygen(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "path for the new private key (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(stderr, "keygen: --out is required")
		return 2
	}
	pub, priv, err := ed25519.GenerateKey(signRandReader)
	if err != nil {
		return die(stderr, "keygen: %v", err)
	}
	if err := signWriteFile(*out, priv, 0o600); err != nil {
		return die(stderr, "write key: %v", err)
	}
	fmt.Fprintf(stderr, "wrote private key (mode 0600): %s\npublic key (embed via -ldflags): %s\n",
		*out, hex.EncodeToString(pub))
	return 0
}

func cmdSign(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "", "path to the Ed25519 private key (required)")
	inPath := fs.String("in", "", "file to sign (required)")
	outPath := fs.String("out", "", "signature output (default: <in>.sig)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *keyPath == "" || *inPath == "" {
		fmt.Fprintln(stderr, "sign: --key and --in are required")
		return 2
	}
	priv, err := signReadFile(*keyPath)
	if err != nil {
		return die(stderr, "read key: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return die(stderr, "key must be %d raw bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	body, err := signReadFile(*inPath)
	if err != nil {
		return die(stderr, "read input: %v", err)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(priv), body)
	dst := *outPath
	if dst == "" {
		dst = *inPath + ".sig"
	}
	if err := signWriteFile(dst, sig, 0o644); err != nil {
		return die(stderr, "write sig: %v", err)
	}
	fmt.Fprintf(stderr, "wrote signature: %s (%d bytes)\n", dst, len(sig))
	return 0
}

func cmdPubkey(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "", "path to the Ed25519 private key (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *keyPath == "" {
		fmt.Fprintln(stderr, "pubkey: --key is required")
		return 2
	}
	priv, err := signReadFile(*keyPath)
	if err != nil {
		return die(stderr, "read key: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return die(stderr, "key must be %d raw bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	pub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
	fmt.Fprintln(stdout, hex.EncodeToString(pub))
	return 0
}

func cmdVerify(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rootsHex := fs.String("roots-hex", "", "comma-separated Ed25519 public keys pinned by the binary (required)")
	keysPath := fs.String("keys", "", "KEYS file path (required)")
	keysSigPath := fs.String("keys-sig", "", "KEYS signature path (required)")
	tarballPath := fs.String("tarball", "", "release tarball path (required)")
	tarballSigPath := fs.String("tarball-sig", "", "release tarball signature path (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *rootsHex == "" || *keysPath == "" || *keysSigPath == "" || *tarballPath == "" || *tarballSigPath == "" {
		fmt.Fprintln(stderr, "verify: --roots-hex, --keys, --keys-sig, --tarball, and --tarball-sig are required")
		return 2
	}

	pinned, err := parseRootsHex(*rootsHex)
	if err != nil {
		return die(stderr, "parse roots: %v", err)
	}
	keysFile, err := signReadFile(*keysPath)
	if err != nil {
		return die(stderr, "read KEYS: %v", err)
	}
	keysSig, err := signReadFile(*keysSigPath)
	if err != nil {
		return die(stderr, "read KEYS signature: %v", err)
	}
	trustedKeys, err := release.VerifyKEYS(keysFile, keysSig, pinned)
	if err != nil {
		return die(stderr, "verify KEYS: %v", err)
	}
	tarball, err := signReadFile(*tarballPath)
	if err != nil {
		return die(stderr, "read tarball: %v", err)
	}
	tarballSig, err := signReadFile(*tarballSigPath)
	if err != nil {
		return die(stderr, "read tarball signature: %v", err)
	}
	signerFP, err := release.VerifyTarball(tarball, tarballSig, trustedKeys)
	if err != nil {
		return die(stderr, "verify tarball: %v", err)
	}
	fmt.Fprintf(stdout, "verified upgrade artifacts signed by %s\n", signerFP)
	return 0
}

func parseRootsHex(raw string) ([][]byte, error) {
	parts := strings.Split(raw, ",")
	out := make([][]byte, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, err := hex.DecodeString(part)
		if err != nil {
			return nil, err
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key must be %d bytes, got %d", ed25519.PublicKeySize, len(key))
		}
		out = append(out, key)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no roots provided")
	}
	return out, nil
}

func die(stderr io.Writer, format string, args ...any) int {
	fmt.Fprintf(stderr, format+"\n", args...)
	return 1
}
