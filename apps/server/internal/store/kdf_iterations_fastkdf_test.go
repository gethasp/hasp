//go:build hasp_test_fastkdf

package store

import "testing"

// TestPasswordIterationsUseFastKDFConstantsUnderTag locks in the contract that
// running `go test -tags=hasp_test_fastkdf` switches the package-level
// passwordIterations to the cheap test cost. Without the tag this test does
// not compile, which is exactly what we want — there must be no other code
// path that downgrades production iteration counts.
func TestPasswordIterationsUseFastKDFConstantsUnderTag(t *testing.T) {
	if passwordIterations != testPasswordIterations {
		t.Fatalf("passwordIterations = %d under hasp_test_fastkdf, want %d", passwordIterations, testPasswordIterations)
	}
	if defaultPasswordIterations != testPasswordIterations {
		t.Fatalf("defaultPasswordIterations = %d under hasp_test_fastkdf, want %d", defaultPasswordIterations, testPasswordIterations)
	}
	if minPasswordIterations != 1 {
		t.Fatalf("minPasswordIterations = %d under hasp_test_fastkdf, want 1", minPasswordIterations)
	}
}
