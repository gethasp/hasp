//go:build darwin && cgo && !hasp_no_attestation

package httpapi

import (
	"errors"
	"os"
	"testing"
)

func TestVerifyPIDDesignatedRequirementExercisesSecurityFramework(t *testing.T) {
	requirement, err := HASPAppDesignatedRequirement("TEAMID1234")
	if err != nil {
		t.Fatalf("build requirement: %v", err)
	}
	err = verifyPIDDesignatedRequirement(os.Getpid(), requirement)
	if !errors.Is(err, ErrAttestationRejected) {
		t.Fatalf("expected current test process to fail HASP.app DR via Security.framework, got %v", err)
	}
}
