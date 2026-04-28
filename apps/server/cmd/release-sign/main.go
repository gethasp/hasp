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
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usageAndExit()
	}
	switch os.Args[1] {
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "tarball", "keys", "sign":
		cmdSign(os.Args[2:])
	case "pubkey":
		cmdPubkey(os.Args[2:])
	default:
		usageAndExit()
	}
}

func usageAndExit() {
	fmt.Fprintln(os.Stderr, "usage: sign keygen|tarball|keys|pubkey [flags]")
	os.Exit(2)
}

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "path for the new private key (required)")
	_ = fs.Parse(args)
	if *out == "" {
		fmt.Fprintln(os.Stderr, "keygen: --out is required")
		os.Exit(2)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		die("keygen: %v", err)
	}
	if err := os.WriteFile(*out, priv, 0o600); err != nil {
		die("write key: %v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote private key (mode 0600): %s\npublic key (embed via -ldflags): %s\n",
		*out, hex.EncodeToString(pub))
}

func cmdSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to the Ed25519 private key (required)")
	inPath := fs.String("in", "", "file to sign (required)")
	outPath := fs.String("out", "", "signature output (default: <in>.sig)")
	_ = fs.Parse(args)
	if *keyPath == "" || *inPath == "" {
		fmt.Fprintln(os.Stderr, "sign: --key and --in are required")
		os.Exit(2)
	}
	priv, err := os.ReadFile(*keyPath)
	if err != nil {
		die("read key: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		die("key must be %d raw bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	body, err := os.ReadFile(*inPath)
	if err != nil {
		die("read input: %v", err)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(priv), body)
	dst := *outPath
	if dst == "" {
		dst = *inPath + ".sig"
	}
	if err := os.WriteFile(dst, sig, 0o644); err != nil {
		die("write sig: %v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote signature: %s (%d bytes)\n", dst, len(sig))
}

func cmdPubkey(args []string) {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to the Ed25519 private key (required)")
	_ = fs.Parse(args)
	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "pubkey: --key is required")
		os.Exit(2)
	}
	priv, err := os.ReadFile(*keyPath)
	if err != nil {
		die("read key: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		die("key must be %d raw bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	pub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
	fmt.Println(hex.EncodeToString(pub))
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
