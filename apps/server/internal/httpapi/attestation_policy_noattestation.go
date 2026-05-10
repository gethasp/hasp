//go:build !darwin || !cgo || hasp_no_attestation

package httpapi

func allowClipboardRevealWithoutAttestation() bool {
	return true
}
