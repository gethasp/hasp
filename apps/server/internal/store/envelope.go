package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var (
	jsonMarshalFn       = json.Marshal
	jsonMarshalIndentFn = json.MarshalIndent
)

func (s *Store) writeEnvelope(vaultKey []byte, state persistedState, header envelopeHeader) error {
	data, err := sealState(vaultKey, state)
	if err != nil {
		return err
	}
	return s.writeEnvelopeFile(fileEnvelope{Header: header, Data: data})
}

func (s *Store) readEnvelope() (fileEnvelope, error) {
	data, err := os.ReadFile(s.paths.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return fileEnvelope{}, ErrVaultNotInitialized
	}
	if err != nil {
		return fileEnvelope{}, fmt.Errorf("read vault: %w", err)
	}
	var envelope fileEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fileEnvelope{}, fmt.Errorf("decode vault: %w", err)
	}
	return envelope, nil
}

func (s *Store) writeEnvelopeFile(envelope fileEnvelope) error {
	if err := os.MkdirAll(filepath.Dir(s.paths.StatePath), 0o700); err != nil {
		return fmt.Errorf("create vault dir: %w", err)
	}
	data, err := jsonMarshalIndentFn(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("encode vault: %w", err)
	}
	tmp := s.paths.StatePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write temp vault: %w", err)
	}
	return os.Rename(tmp, s.paths.StatePath)
}

func sealState(vaultKey []byte, state persistedState) (sealedBlob, error) {
	if state.Items == nil {
		state.Items = map[string]Item{}
	}
	data, err := jsonMarshalFn(state)
	if err != nil {
		return sealedBlob{}, fmt.Errorf("marshal state: %w", err)
	}
	return sealBytes(vaultKey, data)
}

func readState(vaultKey []byte, blob sealedBlob) (persistedState, error) {
	data, err := openBytes(vaultKey, blob)
	if err != nil {
		return persistedState{}, err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return persistedState{}, fmt.Errorf("decode state: %w", err)
	}
	if state.Items == nil {
		state.Items = map[string]Item{}
	}
	if state.Bindings == nil {
		state.Bindings = map[string]Binding{}
	}
	if state.ProjectLeases == nil {
		state.ProjectLeases = map[string]ProjectLease{}
	}
	if state.SecretGrants == nil {
		state.SecretGrants = map[string]SecretGrant{}
	}
	if state.ConvenienceGrants == nil {
		state.ConvenienceGrants = map[string]ConvenienceGrant{}
	}
	return state, nil
}
