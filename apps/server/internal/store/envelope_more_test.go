package store

import (
	"context"
	"testing"
)

func TestWriteEnvelopeFileAndReadEnvelopeRoundTrip(t *testing.T) {
	store := newTestStore(t)
	envelope := fileEnvelope{
		Header: envelopeHeader{Version: 1},
		Data:   sealedBlob{Nonce: "AA==", Ciphertext: "AA=="},
	}
	if err := store.writeEnvelopeFile(envelope); err != nil {
		t.Fatalf("write envelope file: %v", err)
	}
	readBack, err := store.readEnvelope()
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	if readBack.Header.Version != envelope.Header.Version {
		t.Fatalf("header version = %d", readBack.Header.Version)
	}
}

func TestSealStateInitializesNilMaps(t *testing.T) {
	blob, err := sealState(make([]byte, keyLength), persistedState{})
	if err != nil {
		t.Fatalf("seal state: %v", err)
	}
	state, err := readState(make([]byte, keyLength), blob)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if state.Items == nil || state.Bindings == nil || state.ProjectLeases == nil || state.SecretGrants == nil || state.ConvenienceGrants == nil {
		t.Fatal("expected state maps initialized")
	}
}

func TestOpenWithPasswordFailsWhenVaultMissing(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.OpenWithPassword(context.Background(), "correct horse battery staple"); err != ErrVaultNotInitialized {
		t.Fatalf("expected vault not initialized, got %v", err)
	}
}
