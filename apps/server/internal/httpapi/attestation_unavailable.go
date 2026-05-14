//go:build !darwin || !cgo || hasp_no_attestation || hasp_test_fastkdf

package httpapi

import "fmt"

func verifyPIDDesignatedRequirement(pid int, _ string) error {
	if pid <= 0 {
		return fmt.Errorf("%w: pid must be positive", ErrAttestationRejected)
	}
	return ErrAttestationUnavailable
}
