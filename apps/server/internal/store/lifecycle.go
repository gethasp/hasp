package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
)

// auditKeyDomain isolates the audit HMAC key from any other key derived
// from the vault DEK. Bumping the suffix forces a scheme migration; the
// const value is part of the on-disk verification contract.
const auditKeyDomain = "hasp-audit-v1"

var (
	resolvePathsFn = paths.Resolve
	newAuditLogFn  = audit.New
	mkdirAllFn     = os.MkdirAll
	statFn         = os.Stat
	randomBytesFn  = randomBytes
	deriveWrapFn   = derivePasswordWrap
	sealBytesFn    = sealBytes
	deriveSpecFn   = deriveFromSpec
	openBytesFn    = openBytes
	readStateFn    = readState
)

func New(keyring Keyring) (*Store, error) {
	resolved, err := resolvePathsFn()
	if err != nil {
		return nil, err
	}
	log, err := newAuditLogFn()
	if err != nil {
		return nil, err
	}
	if keyring == nil {
		keyring = unsupportedKeyring{}
	}
	return &Store{
		paths:   resolved,
		keyring: keyring,
		audit:   log,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}, nil
}

func (s *Store) Init(_ context.Context, masterPassword string) error {
	if err := validateMasterPassword(masterPassword); err != nil {
		return err
	}
	if err := mkdirAllFn(s.paths.HomeDir, 0o700); err != nil {
		return fmt.Errorf("create home dir: %w", err)
	}
	if _, err := statFn(s.paths.StatePath); err == nil {
		return ErrVaultExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat vault: %w", err)
	}

	vaultKey, err := randomBytesFn(keyLength)
	if err != nil {
		return err
	}
	kdf, wrapKey, err := deriveWrapFn(masterPassword)
	if err != nil {
		return err
	}
	passwordWrap, err := sealBytesFn(wrapKey, vaultKey)
	if err != nil {
		return err
	}
	state := persistedState{
		Items:             map[string]Item{},
		Bindings:          map[string]Binding{},
		ProjectLeases:     map[string]ProjectLease{},
		SecretGrants:      map[string]SecretGrant{},
		ConvenienceGrants: map[string]ConvenienceGrant{},
		PlaintextGrants:   map[string]PlaintextGrant{},
		MutationGrants:    map[string]MutationGrant{},
		ManifestReviews:   map[string]ManifestReview{},
	}
	if err := s.writeEnvelope(vaultKey, state, envelopeHeader{
		Version:      formatVersion,
		CreatedAt:    s.now(),
		UpdatedAt:    s.now(),
		KDF:          kdf,
		PasswordWrap: passwordWrap,
	}); err != nil {
		return err
	}
	s.appendAuditBestEffort(audit.EventInit, "user", map[string]any{"state_path": s.paths.StatePath})
	return nil
}

func (s *Store) OpenWithPassword(_ context.Context, masterPassword string) (*Handle, error) {
	envelope, err := s.readEnvelope()
	if err != nil {
		return nil, err
	}
	wrapKey, err := deriveSpecFn(masterPassword, envelope.Header.KDF)
	if err != nil {
		return nil, err
	}
	vaultKey, err := openBytesFn(wrapKey, envelope.Header.PasswordWrap)
	if err != nil {
		return nil, ErrInvalidPassword
	}
	state, err := readStateFn(vaultKey, envelope.Data)
	if err != nil {
		if errors.Is(err, errCipherAuth) {
			// vaultKey unwrapped fine but the data blob refused to authenticate.
			// Operationally the caller fixes this by retyping the password, not
			// by rebuilding the envelope, so report it the same as a wrong wrap.
			return nil, ErrInvalidPassword
		}
		return nil, fmt.Errorf("decrypt state: %w", err)
	}
	return &Handle{store: s, state: state, vaultKey: vaultKey}, nil
}

func (s *Store) OpenWithConvenienceUnlock(_ context.Context) (*Handle, error) {
	envelope, err := s.readEnvelope()
	if err != nil {
		return nil, err
	}
	if envelope.Header.ConvenienceWrap == nil {
		return nil, fmt.Errorf("%w: no saved convenience key is configured for this vault", ErrKeyringUnavailable)
	}
	deviceKey, err := s.keyring.Get(keyringService, s.keyringAccount())
	if err != nil {
		return nil, fmt.Errorf("%w: keychain read failed: %v", ErrKeyringUnavailable, err)
	}
	decodedKey, err := decodeConvenienceKey(deviceKey)
	if err != nil {
		return nil, fmt.Errorf("%w: stored convenience key is invalid", ErrKeyringUnavailable)
	}
	vaultKey, err := openBytesFn(decodedKey, *envelope.Header.ConvenienceWrap)
	if err != nil {
		return nil, fmt.Errorf("%w: stored convenience key no longer matches this vault", ErrKeyringUnavailable)
	}
	state, err := readStateFn(vaultKey, envelope.Data)
	if err != nil {
		if errors.Is(err, errCipherAuth) {
			return nil, fmt.Errorf("%w: stored convenience key no longer authenticates this vault", ErrKeyringUnavailable)
		}
		return nil, fmt.Errorf("decrypt state: %w", err)
	}
	return &Handle{store: s, state: state, vaultKey: vaultKey}, nil
}

func (h *Handle) EnableConvenienceUnlock(ctx context.Context) error {
	envelope, err := h.store.readEnvelope()
	if err != nil {
		return err
	}
	deviceKey, err := randomBytesFn(keyLength)
	if err != nil {
		return err
	}
	wrap, err := sealBytesFn(deviceKey, h.vaultKey)
	if err != nil {
		return err
	}
	if err := h.store.keyring.Set(ctx, keyringService, h.store.keyringAccount(), encodeConvenienceKey(deviceKey)); err != nil {
		return fmt.Errorf("%w: keychain write failed: %v", ErrKeyringUnavailable, err)
	}
	envelope.Header.ConvenienceWrap = &wrap
	envelope.Header.UpdatedAt = h.store.now()
	return h.store.writeEnvelopeFile(envelope)
}

// DisableConvenienceUnlock is hasp's "forget-device" primitive: it rips the
// keychain-backed unlock shortcut out of the vault so a future
// OpenWithConvenienceUnlock must fail closed. It does two independent things
// and both must happen even when one leg fails:
//
//  1. Clears envelope.Header.ConvenienceWrap so the on-disk vault alone is
//     useless to an attacker who later steals the keychain blob.
//  2. Deletes the keychain entry so a same-UID attacker cannot read the
//     wrapped key off disk and replay it.
//
// Ordering: we clear-and-persist the envelope first. If the keychain delete
// subsequently fails (user revoked keychain access, keychain offline, etc.)
// the envelope mutation still stands, which is the fail-closed posture the
// caller wants — we prefer a leaked orphan keychain entry over a live
// convenience wrap. The keychain error is returned so the caller can warn
// the operator that residual keychain material may still exist.
//
// hadWrap reports whether there was a ConvenienceWrap to clear, letting
// `hasp vault forget-device` print a meaningful "already cleared" line
// on a second invocation.
func (h *Handle) DisableConvenienceUnlock(_ context.Context) (bool, error) {
	envelope, err := h.store.readEnvelope()
	if err != nil {
		return false, err
	}
	hadWrap := envelope.Header.ConvenienceWrap != nil
	if !hadWrap {
		// Idempotent no-op. We skip the keychain Delete here so that callers
		// wrapping this into `hasp vault lock` do not fail on vaults that
		// never enabled convenience unlock — platform keyrings (e.g. the
		// macOS `security` CLI) surface "item not found" as a generic error
		// that is expensive to distinguish from real failures.
		return false, nil
	}
	envelope.Header.ConvenienceWrap = nil
	envelope.Header.UpdatedAt = h.store.now()
	if err := h.store.writeEnvelopeFile(envelope); err != nil {
		return false, fmt.Errorf("clear convenience wrap: %w", err)
	}
	if err := h.store.keyring.Delete(keyringService, h.store.keyringAccount()); err != nil && !errors.Is(err, ErrKeyringUnavailable) {
		return hadWrap, fmt.Errorf("forget keychain entry: %w", err)
	}
	return hadWrap, nil
}

// RekdfWithPassword rewrites the envelope's PasswordWrap under the binary's
// current default KDF (e.g. argon2id) without rotating the underlying vault
// key. The DEK that seals every item, binding, and grant is preserved across
// the call, so all sealed-under-DEK material survives unchanged — only the
// password→DEK wrap is re-derived under the new primitive.
//
// The caller must supply the current master password. The method re-derives
// the OLD wrap key against the on-disk kdfSpec and verifies it unwraps the
// recorded PasswordWrap before writing anything; this fails closed on a wrong
// password instead of grinding through silent rewrites that would let an
// adversary use rekdf as a password oracle. A wrong password returns
// ErrInvalidPassword.
//
// Returns the previous and new KDF names so the caller can render an honest
// "upgraded foo → bar" message; an envelope already on the binary's current
// default still gets rewritten (with a fresh salt) and returns oldKDF == newKDF.
//
// The convenience wrap is intentionally left untouched — it wraps the SAME
// vault key under a separate device key derived independently of the password
// path, so the password→DEK rewrap doesn't invalidate it.
func (h *Handle) RekdfWithPassword(_ context.Context, masterPassword string) (string, string, error) {
	envelope, err := h.store.readEnvelope()
	if err != nil {
		return "", "", err
	}
	oldKDF := envelope.Header.KDF.Name
	if oldKDF == "" {
		// Envelopes written before the dispatch table existed always meant
		// pbkdf2-sha256; report it that way so the caller's audit/UX surfaces
		// don't print a confusing empty algorithm name.
		oldKDF = "pbkdf2-sha256"
	}

	oldWrapKey, err := deriveSpecFn(masterPassword, envelope.Header.KDF)
	if err != nil {
		return oldKDF, "", err
	}
	if _, err := openBytesFn(oldWrapKey, envelope.Header.PasswordWrap); err != nil {
		return oldKDF, "", ErrInvalidPassword
	}

	newSpec, newWrapKey, err := deriveWrapFn(masterPassword)
	if err != nil {
		return oldKDF, "", err
	}
	newPasswordWrap, err := sealBytesFn(newWrapKey, h.vaultKey)
	if err != nil {
		return oldKDF, newSpec.Name, err
	}

	envelope.Header.KDF = newSpec
	envelope.Header.PasswordWrap = newPasswordWrap
	envelope.Header.UpdatedAt = h.store.now()
	if err := h.store.writeEnvelopeFile(envelope); err != nil {
		return oldKDF, newSpec.Name, err
	}
	h.store.appendAuditBestEffort(audit.EventRekdf, "user", map[string]any{
		"from": oldKDF,
		"to":   newSpec.Name,
	})
	return oldKDF, newSpec.Name, nil
}

// RekeyPassword rotates the master password without rotating the underlying
// vault key. The DEK that seals every item, binding, and grant is preserved,
// so all sealed-under-DEK material survives the call — only the
// password→DEK wrap is re-derived under the new password.
//
// The caller must supply the current master password. This method re-derives
// the OLD wrap key against the on-disk kdfSpec and verifies it unwraps the
// recorded PasswordWrap before writing anything; this fails closed on a wrong
// password (returning ErrInvalidPassword) instead of grinding through silent
// rewrites that would let an adversary use rekey as a password oracle.
//
// The convenience wrap is cleared as part of the rotation: the device-key
// path holds an independent unwrap of the SAME vault key, so leaving it in
// place would let a stolen keychain replay resurrect the rotated password's
// access. Operators who want convenience unlock back must opt in again under
// the new password.
func (h *Handle) RekeyPassword(_ context.Context, oldPassword, newPassword string) error {
	if err := validateMasterPassword(oldPassword); err != nil {
		return err
	}
	if err := validateMasterPassword(newPassword); err != nil {
		return err
	}
	envelope, err := h.store.readEnvelope()
	if err != nil {
		return err
	}
	oldWrapKey, err := deriveSpecFn(oldPassword, envelope.Header.KDF)
	if err != nil {
		return err
	}
	if _, err := openBytesFn(oldWrapKey, envelope.Header.PasswordWrap); err != nil {
		return ErrInvalidPassword
	}

	newSpec, newWrapKey, err := deriveWrapFn(newPassword)
	if err != nil {
		return err
	}
	newPasswordWrap, err := sealBytesFn(newWrapKey, h.vaultKey)
	if err != nil {
		return err
	}

	envelope.Header.KDF = newSpec
	envelope.Header.PasswordWrap = newPasswordWrap
	envelope.Header.ConvenienceWrap = nil
	envelope.Header.UpdatedAt = h.store.now()
	if err := h.store.writeEnvelopeFile(envelope); err != nil {
		return err
	}
	h.store.appendAuditBestEffort(audit.EventRekey, "user", map[string]any{
		"convenience_cleared": true,
	})
	return nil
}

// AuditHMACKey derives the HMAC key the audit log uses to authenticate
// chain hashes. Derivation is HMAC-SHA256(vaultKey, auditKeyDomain) so:
//   - the audit key is bound to the vault — locking the vault releases
//     the key from memory along with vaultKey;
//   - the same vault always derives the same audit key, so a cold
//     `hasp audit verify` after restart re-derives and verifies cleanly;
//   - rotating the vault key (future rekey work) automatically rotates
//     the audit key, breaking the chain on purpose so a past attacker
//     who learned the old key cannot forge events under the new one.
//
// Returns a 32-byte slice owned by the caller.
func (h *Handle) AuditHMACKey() []byte {
	if h == nil || len(h.vaultKey) == 0 {
		return nil
	}
	mac := hmac.New(sha256.New, h.vaultKey)
	mac.Write([]byte(auditKeyDomain))
	return mac.Sum(nil)
}

func (s *Store) keyringAccount() string {
	sum := sha256Sum([]byte(s.paths.HomeDir))
	return fmt.Sprintf("vault:%x", sum[:8])
}

func encodeConvenienceKey(value []byte) string {
	return hex.EncodeToString(value)
}

func decodeConvenienceKey(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, ErrKeyringUnavailable
	}
	if decoded, err := hex.DecodeString(trimmed); err == nil && len(decoded) > 0 {
		return decoded, nil
	}
	return []byte(value), nil
}

func validateMasterPassword(masterPassword string) error {
	if strings.TrimSpace(masterPassword) == "" {
		return errors.New("master password is required")
	}
	return nil
}
