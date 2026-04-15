package store

import (
	"crypto/cipher"
	"errors"
	"strings"
	"testing"
)

func TestDeriveFromSpecRejectsBadSalt(t *testing.T) {
	if _, err := deriveFromSpec("password", kdfSpec{Salt: "%%%"}); err == nil {
		t.Fatal("expected bad salt decode failure")
	}
}

func TestSealAndOpenBytesRoundTrip(t *testing.T) {
	key := make([]byte, keyLength)
	blob, err := sealBytes(key, []byte("hello"))
	if err != nil {
		t.Fatalf("seal bytes: %v", err)
	}
	opened, err := openBytes(key, blob)
	if err != nil {
		t.Fatalf("open bytes: %v", err)
	}
	if string(opened) != "hello" {
		t.Fatalf("opened bytes = %q", string(opened))
	}
}

func TestCryptoHelpersErrorPaths(t *testing.T) {
	lockStoreSeams(t)
	origNewGCM := newGCMFn
	origRandRead := randReadFn
	defer func() {
		newGCMFn = origNewGCM
		randReadFn = origRandRead
	}()

	newGCMFn = origNewGCM
	randReadFn = func([]byte) (int, error) { return 0, errors.New("entropy fail") }
	if _, _, err := derivePasswordWrap("password"); err == nil {
		t.Fatal("expected derivePasswordWrap random failure")
	}
	if _, err := sealBytes(make([]byte, keyLength), []byte("hello")); err == nil {
		t.Fatal("expected sealBytes nonce random failure")
	}
	if _, err := randomBytes(4); err == nil {
		t.Fatal("expected randomBytes failure")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected randomHex panic")
			}
		}()
		_ = randomHex(4)
	}()

	randReadFn = origRandRead
	newGCMFn = func(cipher.Block) (cipher.AEAD, error) { return nil, errors.New("gcm fail") }
	if _, err := sealBytes(make([]byte, keyLength), []byte("hello")); err == nil {
		t.Fatal("expected sealBytes GCM failure")
	}
	if _, err := openBytes(make([]byte, keyLength), sealedBlob{}); err == nil {
		t.Fatal("expected openBytes GCM failure")
	}

	newGCMFn = origNewGCM
	if _, err := sealBytes([]byte("short"), []byte("hello")); err == nil {
		t.Fatal("expected sealBytes invalid key failure")
	}
	if _, err := openBytes([]byte("short"), sealedBlob{}); err == nil {
		t.Fatal("expected openBytes invalid key failure")
	}
	if _, err := openBytes(make([]byte, keyLength), sealedBlob{Nonce: "AA==", Ciphertext: ""}); err == nil || !strings.Contains(err.Error(), "invalid nonce size") {
		t.Fatalf("expected invalid nonce size, got %v", err)
	}
	if _, err := openBytes(make([]byte, keyLength), sealedBlob{Nonce: "AAAAAAAAAAAAAAAA", Ciphertext: "AA=="}); err == nil {
		t.Fatal("expected authentication failure")
	}
}
