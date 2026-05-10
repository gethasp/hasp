package leases

import (
	"testing"
	"time"
)

func TestListStableCursorSurvivesPriorRowRemoval(t *testing.T) {
	base := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	input := []Lease{
		{ID: "a", GrantedAt: base.Add(3 * time.Minute), Status: "active"},
		{ID: "b", GrantedAt: base.Add(2 * time.Minute), Status: "active"},
		{ID: "c", GrantedAt: base.Add(1 * time.Minute), Status: "active"},
	}

	first := List(input, ListOptions{Limit: 2, Status: "active", Now: base})
	if len(first.Leases) != 2 || !first.HasMore || first.NextCursor == "" {
		t.Fatalf("first page = %+v, want two rows with stable next cursor", first)
	}

	afterRemoval := List(input[1:], ListOptions{Limit: 2, Status: "active", Cursor: first.NextCursor, Now: base})
	if len(afterRemoval.Leases) != 1 || afterRemoval.Leases[0].ID != "c" {
		t.Fatalf("page after prior row removal = %+v, want lease c", afterRemoval)
	}
}
