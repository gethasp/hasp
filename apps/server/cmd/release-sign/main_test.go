package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("random") }

func resetSignSeams(t *testing.T) {
	t.Helper()
	origRand := signRandReader
	origRead := signReadFile
	origWrite := signWriteFile
	origExit := signExit
	t.Cleanup(func() {
		signRandReader = origRand
		signReadFile = origRead
		signWriteFile = origWrite
		signExit = origExit
	})
}

type exitPanic int

func TestMainEntrypoint(t *testing.T) {
	resetSignSeams(t)
	origArgs := os.Args
	os.Args = []string{"release-sign"}
	t.Cleanup(func() { os.Args = origArgs })
	signExit = func(code int) { panic(exitPanic(code)) }
	defer func() {
		got, ok := recover().(exitPanic)
		if !ok {
			t.Fatalf("main did not exit through signExit")
		}
		if got != 2 {
			t.Fatalf("exit = %d", got)
		}
	}()
	main()
}

func TestRunUsageAndFlagErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"bogus"},
		{"keygen", "--bogus"},
		{"sign", "--bogus"},
		{"pubkey", "--bogus"},
		{"keygen"},
		{"sign"},
		{"pubkey"},
	} {
		var stderr bytes.Buffer
		if code := run(args, ioDiscard{}, &stderr); code != 2 {
			t.Fatalf("run(%v) exit = %d, stderr=%q", args, code, stderr.String())
		}
	}
}

func TestKeygenSuccessAndFailures(t *testing.T) {
	resetSignSeams(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "hasp-key")
	var stderr bytes.Buffer
	if code := run([]string{"keygen", "--out", keyPath}, ioDiscard{}, &stderr); code != 0 {
		t.Fatalf("keygen exit = %d, stderr=%q", code, stderr.String())
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		t.Fatalf("key size = %d", len(raw))
	}
	if !strings.Contains(stderr.String(), "public key") {
		t.Fatalf("missing public key output: %q", stderr.String())
	}

	signRandReader = failingReader{}
	stderr.Reset()
	if code := run([]string{"keygen", "--out", filepath.Join(dir, "bad-rand")}, ioDiscard{}, &stderr); code != 1 {
		t.Fatalf("keygen random exit = %d, stderr=%q", code, stderr.String())
	}

	signRandReader = bytes.NewReader(bytes.Repeat([]byte{1}, 256))
	signWriteFile = func(string, []byte, os.FileMode) error { return errors.New("write") }
	stderr.Reset()
	if code := run([]string{"keygen", "--out", filepath.Join(dir, "bad-write")}, ioDiscard{}, &stderr); code != 1 {
		t.Fatalf("keygen write exit = %d, stderr=%q", code, stderr.String())
	}
}

func TestSignSuccessAndFailures(t *testing.T) {
	resetSignSeams(t)
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	keyPath := filepath.Join(dir, "key")
	inPath := filepath.Join(dir, "artifact")
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(inPath, []byte("artifact"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	var stderr bytes.Buffer
	if code := run([]string{"sign", "--key", keyPath, "--in", inPath}, ioDiscard{}, &stderr); code != 0 {
		t.Fatalf("sign exit = %d, stderr=%q", code, stderr.String())
	}
	sig, err := os.ReadFile(inPath + ".sig")
	if err != nil {
		t.Fatalf("read default sig: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature size = %d", len(sig))
	}

	customSig := filepath.Join(dir, "custom.sig")
	stderr.Reset()
	if code := run([]string{"keys", "--key", keyPath, "--in", inPath, "--out", customSig}, ioDiscard{}, &stderr); code != 0 {
		t.Fatalf("keys sign exit = %d, stderr=%q", code, stderr.String())
	}
	if _, err := os.Stat(customSig); err != nil {
		t.Fatalf("custom sig missing: %v", err)
	}

	badKey := filepath.Join(dir, "bad-key")
	if err := os.WriteFile(badKey, []byte("short"), 0o600); err != nil {
		t.Fatalf("write bad key: %v", err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing key file", []string{"tarball", "--key", filepath.Join(dir, "missing"), "--in", inPath}},
		{"bad key length", []string{"tarball", "--key", badKey, "--in", inPath}},
		{"missing input", []string{"tarball", "--key", keyPath, "--in", filepath.Join(dir, "missing")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stderr.Reset()
			if code := run(tc.args, ioDiscard{}, &stderr); code != 1 {
				t.Fatalf("exit = %d, stderr=%q", code, stderr.String())
			}
		})
	}

	signWriteFile = func(string, []byte, os.FileMode) error { return errors.New("write") }
	stderr.Reset()
	if code := run([]string{"sign", "--key", keyPath, "--in", inPath, "--out", filepath.Join(dir, "blocked")}, ioDiscard{}, &stderr); code != 1 {
		t.Fatalf("write sig exit = %d, stderr=%q", code, stderr.String())
	}
}

func TestPubkeySuccessAndFailures(t *testing.T) {
	resetSignSeams(t)
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"pubkey", "--key", keyPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("pubkey exit = %d, stderr=%q", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != hex.EncodeToString(pub) {
		t.Fatalf("pubkey = %q", got)
	}

	if code := run([]string{"pubkey", "--key", filepath.Join(dir, "missing")}, &stdout, &stderr); code != 1 {
		t.Fatalf("missing key exit = %d", code)
	}
	badKey := filepath.Join(dir, "bad")
	if err := os.WriteFile(badKey, []byte("short"), 0o600); err != nil {
		t.Fatalf("write bad key: %v", err)
	}
	if code := run([]string{"pubkey", "--key", badKey}, &stdout, &stderr); code != 1 {
		t.Fatalf("bad key exit = %d", code)
	}
}

func TestVerifySuccessAndFailures(t *testing.T) {
	resetSignSeams(t)
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	rootsHex := hex.EncodeToString(pub)
	keysPath := filepath.Join(dir, "KEYS-v1.2.3")
	keysSigPath := keysPath + ".sig"
	tarballPath := filepath.Join(dir, "hasp-v1.2.3-darwin-arm64.tar.gz")
	tarballSigPath := tarballPath + ".sig"
	keysBody := []byte(rootsHex + " hasp release signing key\n")
	tarballBody := []byte("tarball")
	if err := os.WriteFile(keysPath, keysBody, 0o644); err != nil {
		t.Fatalf("write keys: %v", err)
	}
	if err := os.WriteFile(keysSigPath, ed25519.Sign(priv, keysBody), 0o644); err != nil {
		t.Fatalf("write keys sig: %v", err)
	}
	if err := os.WriteFile(tarballPath, tarballBody, 0o644); err != nil {
		t.Fatalf("write tarball: %v", err)
	}
	if err := os.WriteFile(tarballSigPath, ed25519.Sign(priv, tarballBody), 0o644); err != nil {
		t.Fatalf("write tarball sig: %v", err)
	}

	args := []string{
		"verify",
		"--roots-hex", rootsHex,
		"--keys", keysPath,
		"--keys-sig", keysSigPath,
		"--tarball", tarballPath,
		"--tarball-sig", tarballSigPath,
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("verify exit = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), rootsHex) {
		t.Fatalf("verify output missing signer: %q", stdout.String())
	}

	stderr.Reset()
	if code := run([]string{"verify"}, ioDiscard{}, &stderr); code != 2 {
		t.Fatalf("missing flags exit = %d, stderr=%q", code, stderr.String())
	}

	tamperedSigPath := filepath.Join(dir, "bad.sig")
	if err := os.WriteFile(tamperedSigPath, bytes.Repeat([]byte{1}, ed25519.SignatureSize), 0o644); err != nil {
		t.Fatalf("write bad sig: %v", err)
	}
	stderr.Reset()
	badArgs := append([]string{}, args...)
	badArgs[len(badArgs)-1] = tamperedSigPath
	if code := run(badArgs, ioDiscard{}, &stderr); code != 1 {
		t.Fatalf("bad tarball sig exit = %d, stderr=%q", code, stderr.String())
	}

	if _, err := parseRootsHex("not-hex"); err == nil {
		t.Fatal("expected bad root hex error")
	}
	if _, err := parseRootsHex(""); err == nil {
		t.Fatal("expected empty roots error")
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
