package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

var (
	newGCMFn   = cipher.NewGCM
	randReadFn = rand.Read
)

func derivePasswordWrap(masterPassword string) (kdfSpec, []byte, error) {
	salt, err := randomBytes(16)
	if err != nil {
		return kdfSpec{}, nil, err
	}
	spec := kdfSpec{
		Name:       "pbkdf2-sha256",
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Iterations: passwordIterations,
		KeyLength:  keyLength,
	}
	key, err := deriveFromSpec(masterPassword, spec)
	return spec, key, err
}

func deriveFromSpec(masterPassword string, spec kdfSpec) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(spec.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	return pbkdf2.Key(sha256.New, masterPassword, salt, spec.Iterations, spec.KeyLength)
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
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func randomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := randReadFn(buf); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return buf, nil
}

func randomHex(size int) string {
	buf, err := randomBytes(size)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", buf)
}

func sha256Sum(value []byte) [32]byte {
	return sha256.Sum256(value)
}
