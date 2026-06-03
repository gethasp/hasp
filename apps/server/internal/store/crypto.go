package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

var (
	newGCMFn   = cipher.NewGCM
	randReadFn = rand.Read
)

const (
	kdfNameArgon2id = "argon2id"
	kdfNamePBKDF2   = "pbkdf2-sha256"
)

// derivePasswordWrap produces a fresh kdfSpec for a NEW vault and the wrap key
// derived from it. Always emits argon2id under the rollout — pbkdf2 stays in the
// READ path (deriveFromSpec) for envelopes written by older binaries.
func derivePasswordWrap(masterPassword string) (kdfSpec, []byte, error) {
	salt, err := randomBytes(16)
	if err != nil {
		return kdfSpec{}, nil, err
	}
	spec := kdfSpec{
		Name:        kdfNameArgon2id,
		Salt:        base64.StdEncoding.EncodeToString(salt),
		KeyLength:   keyLength,
		Time:        passwordArgon2Time,
		Memory:      passwordArgon2MemoryKiB,
		Parallelism: passwordArgon2Parallelism,
	}
	key, err := deriveFromSpec(masterPassword, spec)
	return spec, key, err
}

// deriveFromSpec re-derives the wrap key from the kdfSpec recorded in an
// envelope's header. Dispatches on Name so argon2id and pbkdf2-sha256 vaults
// both unlock cleanly; an unknown algorithm errors loudly rather than silently
// falling through to the wrong primitive.
func deriveFromSpec(masterPassword string, spec kdfSpec) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(spec.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	switch spec.Name {
	case kdfNameArgon2id:
		if spec.Time == 0 || spec.Memory == 0 || spec.Parallelism == 0 {
			return nil, fmt.Errorf("invalid argon2id kdf params (time=%d memory=%d parallelism=%d)", spec.Time, spec.Memory, spec.Parallelism)
		}
		return argon2.IDKey([]byte(masterPassword), salt, spec.Time, spec.Memory, spec.Parallelism, uint32(spec.KeyLength)), nil
	case kdfNamePBKDF2, "":
		// Empty Name preserves the read-path for envelopes written before the
		// dispatch table existed; those entries always meant pbkdf2-sha256.
		if spec.Iterations <= 0 {
			// Mirror the argon2id guard: a tampered or zeroed iteration count
			// would silently derive a one-round key. Fail loudly instead.
			return nil, fmt.Errorf("invalid pbkdf2 kdf params (iterations=%d)", spec.Iterations)
		}
		return pbkdf2.Key(sha256.New, masterPassword, salt, spec.Iterations, spec.KeyLength)
	default:
		return nil, fmt.Errorf("unknown kdf %q in envelope", spec.Name)
	}
}

func sealBytes(key []byte, plaintext []byte) (sealedBlob, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return sealedBlob{}, err
	}
	gcm, err := newGCMFn(block)
	if err != nil {
		return sealedBlob{}, err
	}
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return sealedBlob{}, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return sealedBlob{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// errCipherAuth is the sentinel that openBytes wraps around any AEAD
// authentication failure. Callers (OpenWithPassword, OpenWithConvenienceUnlock)
// use errors.Is to detect "wrong key" without resorting to substring matches
// against the stdlib's "cipher: message authentication failed" string. Shape
// failures (base64 decode, nonce size) are deliberately NOT wrapped with this
// sentinel so genuine envelope corruption keeps its structured error.
var errCipherAuth = errors.New("cipher authentication failed")

func openBytes(key []byte, blob sealedBlob) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCMFn(block)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(blob.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(blob.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	// Fail early on malformed envelopes instead of delegating the shape check to
	// the AEAD implementation, which makes this corruption mode explicit and
	// deterministic across platforms.
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errCipherAuth, err)
	}
	return plaintext, nil
}

func randomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := randReadFn(buf); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return buf, nil
}

func randomHex(size int) (string, error) {
	buf, err := randomBytes(size)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", buf), nil
}

func sha256Sum(value []byte) [32]byte {
	return sha256.Sum256(value)
}
