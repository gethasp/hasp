package runtime

import "testing"

// TestCommitFallsBackToUnknown covers the empty-Commit branch of CommitString().
func TestCommitFallsBackToUnknown(t *testing.T) {
	orig := Commit
	defer func() { Commit = orig }()

	Commit = ""
	if got := CommitString(); got != "unknown" {
		t.Fatalf("CommitString() empty = %q, want unknown", got)
	}

	Commit = "  abc1234  "
	if got := CommitString(); got != "abc1234" {
		t.Fatalf("CommitString() trimmed = %q", got)
	}
}

// TestBuildDateFallsBackToUnknown covers the empty-BuildDate branch.
func TestBuildDateFallsBackToUnknown(t *testing.T) {
	orig := BuildDate
	defer func() { BuildDate = orig }()

	BuildDate = ""
	if got := BuildDateString(); got != "unknown" {
		t.Fatalf("BuildDateString() empty = %q, want unknown", got)
	}

	BuildDate = "  2026-04-24T00:00:00Z  "
	if got := BuildDateString(); got != "2026-04-24T00:00:00Z" {
		t.Fatalf("BuildDateString() trimmed = %q", got)
	}
}
