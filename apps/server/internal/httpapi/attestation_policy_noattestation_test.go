//go:build !darwin || !cgo || hasp_no_attestation || hasp_test_fastkdf

package httpapi

import "testing"

func TestClipboardFallbackAllowedWithoutPlatformAttestation(t *testing.T) {
	if !allowClipboardRevealWithoutAttestation() {
		t.Fatal("clipboard fallback should be allowed without platform attestation")
	}
}
