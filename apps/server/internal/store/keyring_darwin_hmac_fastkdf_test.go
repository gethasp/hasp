//go:build darwin && hasp_test_fastkdf

package store

import (
	"context"
	"errors"
	"testing"
)

func TestDarwinNativeHMACKeyringFastKDFStub(t *testing.T) {
	keyring := DarwinKeyring{}
	if err := keyring.SetWithDesignatedRequirements(context.Background(), "svc", "acct", "value", []string{"app", "daemon"}); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("set designated requirement err = %v", err)
	}
	if _, err := keyring.GetNative("svc", "acct"); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("get native err = %v", err)
	}
	if err := keyring.DeleteNative("svc", "acct"); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("delete native err = %v", err)
	}
}
