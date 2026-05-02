//go:build !darwin

package store

import (
	"context"
	"errors"
	"testing"
)

func TestNewDefaultKeyringUnsupported(t *testing.T) {
	keyring := NewDefaultKeyring()
	if err := keyring.Set(context.Background(), "service", "account", "value"); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("Set error = %v, want ErrKeyringUnavailable", err)
	}
	if _, err := keyring.Get("service", "account"); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("Get error = %v, want ErrKeyringUnavailable", err)
	}
	if err := keyring.Delete("service", "account"); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("Delete error = %v, want ErrKeyringUnavailable", err)
	}
}
