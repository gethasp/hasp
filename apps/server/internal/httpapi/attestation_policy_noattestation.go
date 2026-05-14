//go:build !darwin || !cgo || hasp_no_attestation || hasp_test_fastkdf

package httpapi

func allowClipboardRevealWithoutAttestation() bool {
	return true
}
