//go:build darwin && cgo && !hasp_no_attestation && !hasp_test_fastkdf

package httpapi

import "testing"

func TestClipboardFallbackDisabledWhenDarwinAttestationIsActive(t *testing.T) {
	if allowClipboardRevealWithoutAttestation() {
		t.Fatal("darwin attestation fallback should be disabled by default")
	}
}
