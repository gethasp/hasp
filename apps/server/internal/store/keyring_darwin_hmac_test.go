//go:build darwin && cgo && !hasp_test_fastkdf

package store

import (
	"context"
	"errors"
	"testing"
)

func TestDarwinNativeKeyringHMACErrorBranches(t *testing.T) {
	keyring := DarwinKeyring{}
	if err := keyring.SetWithDesignatedRequirements(context.Background(), "svc", "acct", "value", []string{"only-one"}); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("expected requirement-count error, got %v", err)
	}
	if err := keyring.SetWithDesignatedRequirements(context.Background(), "svc", "acct", "not-base64", []string{"app", "daemon"}); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("expected base64 decode error, got %v", err)
	}
	if _, err := keyring.GetNative("com.gethasp.test.missing", "missing-account"); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("expected native get unavailable/not-found error, got %v", err)
	}
	if err := keyring.DeleteNative("com.gethasp.test.missing", "missing-account"); err != nil {
		t.Fatalf("delete of missing native item should be idempotent, got %v", err)
	}
}
