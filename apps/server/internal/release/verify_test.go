package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	return pub, priv
}

func keysFile(t *testing.T, keys ...ed25519.PublicKey) []byte {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("# hasp release-key bundle (test)\n")
	for i, k := range keys {
		fmt.Fprintf(&sb, "%s key%d\n", hex.EncodeToString(k), i)
	}
	return []byte(sb.String())
}

func TestVerifyKEYSHappyPath(t *testing.T) {
	pinPub, pinPriv := newKey(t)
	rotPub, _ := newKey(t)

	body := keysFile(t, pinPub, rotPub)
	sig := ed25519.Sign(pinPriv, body)

	got, err := VerifyKEYS(body, sig, [][]byte{pinPub})
	if err != nil {
		t.Fatalf("VerifyKEYS: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(got))
	}
}

func TestVerifyKEYSRejectsUnsigned(t *testing.T) {
	pinPub, _ := newKey(t)
	otherPub, otherPriv := newKey(t)

	body := keysFile(t, otherPub)
	sig := ed25519.Sign(otherPriv, body)

	_, err := VerifyKEYS(body, sig, [][]byte{pinPub})
	if !errors.Is(err, ErrUntrustedKEYS) {
		t.Fatalf("expected ErrUntrustedKEYS, got %v", err)
	}
}

func TestVerifyKEYSRejectsTamperedBody(t *testing.T) {
	pinPub, pinPriv := newKey(t)

	body := keysFile(t, pinPub)
	sig := ed25519.Sign(pinPriv, body)

	tampered := append([]byte{}, body...)
	tampered[len(tampered)-2] ^= 0x01

	_, err := VerifyKEYS(tampered, sig, [][]byte{pinPub})
	if !errors.Is(err, ErrUntrustedKEYS) {
		t.Fatalf("expected ErrUntrustedKEYS for tampered body, got %v", err)
	}
}

func TestVerifyKEYSRejectsShortSignature(t *testing.T) {
	pinPub, _ := newKey(t)
	body := keysFile(t, pinPub)
	_, err := VerifyKEYS(body, []byte{0x01, 0x02}, [][]byte{pinPub})
	if !errors.Is(err, ErrUntrustedKEYS) {
		t.Fatalf("expected ErrUntrustedKEYS for short sig, got %v", err)
	}
}

func TestVerifyKEYSRequiresPinnedSet(t *testing.T) {
	pinPub, pinPriv := newKey(t)
	body := keysFile(t, pinPub)
	sig := ed25519.Sign(pinPriv, body)
	_, err := VerifyKEYS(body, sig, nil)
	if !errors.Is(err, ErrNoPinnedKeys) {
		t.Fatalf("expected ErrNoPinnedKeys, got %v", err)
	}
}

func TestVerifyKEYSRejectsMalformedFile(t *testing.T) {
	pinPub, pinPriv := newKey(t)
	body := []byte("not-hex key1\n")
	sig := ed25519.Sign(pinPriv, body)
	_, err := VerifyKEYS(body, sig, [][]byte{pinPub})
	if !errors.Is(err, ErrMalformedKEYS) {
		t.Fatalf("expected ErrMalformedKEYS, got %v", err)
	}
}

func TestVerifyKEYSRejectsEmptyKeyList(t *testing.T) {
	pinPub, pinPriv := newKey(t)
	body := []byte("# only comments\n# nothing else\n")
	sig := ed25519.Sign(pinPriv, body)
	_, err := VerifyKEYS(body, sig, [][]byte{pinPub})
	if !errors.Is(err, ErrMalformedKEYS) {
		t.Fatalf("expected ErrMalformedKEYS for empty key list, got %v", err)
	}
}

func TestVerifyTarballHappyPath(t *testing.T) {
	signerPub, signerPriv := newKey(t)
	tarball := []byte("fake-tarball-bytes")
	sig := ed25519.Sign(signerPriv, tarball)

	fp, err := VerifyTarball(tarball, sig, [][]byte{signerPub})
	if err != nil {
		t.Fatalf("VerifyTarball: %v", err)
	}
	if fp != hex.EncodeToString(signerPub) {
		t.Fatalf("fingerprint mismatch: got %s want %s", fp, hex.EncodeToString(signerPub))
	}
}

func TestVerifyTarballRejectsUnknownSigner(t *testing.T) {
	trustedPub, _ := newKey(t)
	_, otherPriv := newKey(t)
	tarball := []byte("fake-tarball-bytes")
	sig := ed25519.Sign(otherPriv, tarball)

	_, err := VerifyTarball(tarball, sig, [][]byte{trustedPub})
	if !errors.Is(err, ErrUntrustedTarball) {
		t.Fatalf("expected ErrUntrustedTarball, got %v", err)
	}
}

func TestVerifyTarballRejectsTamperedBytes(t *testing.T) {
	signerPub, signerPriv := newKey(t)
	tarball := []byte("fake-tarball-bytes")
	sig := ed25519.Sign(signerPriv, tarball)

	tampered := append([]byte{}, tarball...)
	tampered[0] ^= 0x01
	_, err := VerifyTarball(tampered, sig, [][]byte{signerPub})
	if !errors.Is(err, ErrUntrustedTarball) {
		t.Fatalf("expected ErrUntrustedTarball for tampered tarball, got %v", err)
	}
}

func TestVerifyKEYSRotation(t *testing.T) {
	// Old key signs a KEYS file that lists both old and new. New
	// key signs the tarball. Old binary (pin set = [old]) accepts.
	oldPub, oldPriv := newKey(t)
	newPub, newPriv := newKey(t)

	body := keysFile(t, oldPub, newPub)
	sig := ed25519.Sign(oldPriv, body)
	trusted, err := VerifyKEYS(body, sig, [][]byte{oldPub})
	if err != nil {
		t.Fatalf("VerifyKEYS: %v", err)
	}

	tarball := []byte("rotated-tarball")
	tarballSig := ed25519.Sign(newPriv, tarball)
	if _, err := VerifyTarball(tarball, tarballSig, trusted); err != nil {
		t.Fatalf("post-rotation VerifyTarball: %v", err)
	}
}

func TestPinnedPublicKeysFromHex(t *testing.T) {
	pub, _ := newKey(t)
	restore := SetPinnedKeysForTest(hex.EncodeToString(pub))
	defer restore()

	got := PinnedPublicKeys()
	if len(got) != 1 {
		t.Fatalf("expected 1 pinned key, got %d", len(got))
	}
	if hex.EncodeToString(got[0]) != hex.EncodeToString(pub) {
		t.Fatal("pinned key round-trip mismatch")
	}
}

func TestPinnedPublicKeysSkipsMalformed(t *testing.T) {
	pub, _ := newKey(t)
	restore := SetPinnedKeysForTest("not-hex," + hex.EncodeToString(pub) + ",abcd")
	defer restore()

	got := PinnedPublicKeys()
	if len(got) != 1 {
		t.Fatalf("expected 1 valid pinned key, got %d", len(got))
	}
}

func TestPinnedPublicKeysEmpty(t *testing.T) {
	restore := SetPinnedKeysForTest("")
	defer restore()
	if got := PinnedPublicKeys(); got != nil {
		t.Fatalf("expected nil for empty CSV, got %v", got)
	}
}
