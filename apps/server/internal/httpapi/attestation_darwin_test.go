//go:build darwin && cgo && !hasp_no_attestation && !hasp_test_fastkdf

package httpapi

import (
	"errors"
	"os"
	"testing"
)

func TestVerifyPIDDesignatedRequirementExercisesSecurityFramework(t *testing.T) {
	requirement, err := HASPDaemonDesignatedRequirement("TEAMID1234")
	if err != nil {
		t.Fatalf("build requirement: %v", err)
	}
	err = verifyPIDDesignatedRequirement(os.Getpid(), requirement)
	if !errors.Is(err, ErrAttestationRejected) {
		t.Fatalf("expected current test process to fail HASP HTTP client DR via Security.framework, got %v", err)
	}
}
