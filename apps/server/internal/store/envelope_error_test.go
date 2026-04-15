package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestReadEnvelopeFailsOnMalformedFile(t *testing.T) {
	store := newTestStore(t)
	if err := os.WriteFile(store.paths.StatePath, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("write malformed vault: %v", err)
	}
	if _, err := store.readEnvelope(); err == nil {
		t.Fatal("expected malformed envelope failure")
	}
}

func TestReadStateFailsOnMalformedPayload(t *testing.T) {
	blob, err := sealBytes(make([]byte, keyLength), []byte("not-json"))
	if err != nil {
		t.Fatalf("seal bytes: %v", err)
	}
	if _, err := readState(make([]byte, keyLength), blob); err == nil {
		t.Fatal("expected readState decode failure")
	}
}

func TestOpenBytesFailsOnMalformedNonceAndCiphertext(t *testing.T) {
	if _, err := openBytes(make([]byte, keyLength), sealedBlob{Nonce: "%%%"}); err == nil {
		t.Fatal("expected nonce decode failure")
	}
	if _, err := openBytes(make([]byte, keyLength), sealedBlob{Nonce: "AA==", Ciphertext: "%%%"}); err == nil {
		t.Fatal("expected ciphertext decode failure")
	}
}

func TestImportEnvFileRejectsInvalidLine(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("INVALID_LINE\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	if _, err := handle.ImportEnvFile(path); err == nil {
		t.Fatal("expected invalid env line failure")
	}
}

func TestWriteEnvelopeAndWriteEnvelopeFileFailurePaths(t *testing.T) {
	store := newTestStore(t)
	if err := store.writeEnvelope([]byte("short"), persistedState{}, envelopeHeader{Version: 1}); err == nil {
		t.Fatal("expected writeEnvelope to fail with invalid key length")
	}

	blocker := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	store.paths.StatePath = filepath.Join(blocker, "vault.json")
	if err := store.writeEnvelopeFile(fileEnvelope{}); err == nil {
		t.Fatal("expected writeEnvelopeFile parent creation failure")
	}
}
