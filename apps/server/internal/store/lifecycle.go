package store

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
)

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
		return nil, ErrKeyringUnavailable
	}
	deviceKey, err := s.keyring.Get(keyringService, s.keyringAccount())
	if err != nil {
		return nil, ErrKeyringUnavailable
	}
	decodedKey, err := decodeConvenienceKey(deviceKey)
	if err != nil {
		return nil, ErrKeyringUnavailable
	}
	vaultKey, err := openBytesFn(decodedKey, *envelope.Header.ConvenienceWrap)
	if err != nil {
		return nil, ErrKeyringUnavailable
	}
	state, err := readStateFn(vaultKey, envelope.Data)
	if err != nil {
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
		return ErrKeyringUnavailable
	}
	envelope.Header.ConvenienceWrap = &wrap
	envelope.Header.UpdatedAt = h.store.now()
	return h.store.writeEnvelopeFile(envelope)
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
