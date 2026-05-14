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

func TestListLeaseFiltersCursorsAndDefaults(t *testing.T) {
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	input := []Lease{
		{ID: "same-b", ConsumerID: "agent", SecretID: "api", GrantedAt: now, ExpiresAt: now.Add(30 * time.Minute), Status: "active"},
		{ID: "same-a", ConsumerID: "agent", SecretID: "api", GrantedAt: now, ExpiresAt: now.Add(2 * time.Hour), Status: "active"},
		{ID: "expired", ConsumerID: "agent", GrantedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute), Status: "active"},
		{ID: "revoked", ConsumerID: "agent", GrantedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(time.Minute), Status: "revoked"},
		{ID: "other", ConsumerID: "other", GrantedAt: now.Add(-3 * time.Hour), ExpiresAt: now.Add(time.Minute), Status: "active"},
	}
	filtered := List(input, ListOptions{ConsumerID: "agent", ExpiringIn: time.Hour, Limit: -1, Now: now})
	if filtered.Total != 1 || filtered.Leases[0].ID != "same-b" {
		t.Fatalf("expiring filtered leases = %+v", filtered)
	}
	if got := List(input, ListOptions{Status: "missing", Now: now}); got.Total != 0 {
		t.Fatalf("missing status leases = %+v", got)
	}
	if start := cursorStart(input, "-1"); start != 0 {
		t.Fatalf("negative cursor start = %d", start)
	}
	if start := cursorStart(input, "200"); start != len(input) {
		t.Fatalf("past-end cursor start = %d", start)
	}
	if start := cursorStart(input, "bad"); start != 0 {
		t.Fatalf("bad cursor start = %d", start)
	}
	if start := cursorStart(input, "123|missing"); start != 0 {
		t.Fatalf("missing stable cursor start = %d", start)
	}
	if stableCursor(Lease{ID: "x", GrantedAt: now}) == "" {
		t.Fatal("stable cursor should not be empty")
	}
}

func TestListResidualCursorAndPagingBranches(t *testing.T) {
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	input := []Lease{
		{ID: "b", GrantedAt: now, Status: "active"},
		{ID: "a", GrantedAt: now, Status: "active"},
		{ID: "old", GrantedAt: now.Add(-time.Hour), Status: "active"},
	}
	all := List(input, ListOptions{Limit: DefaultLimit + 10})
	if len(all.Leases) != 3 || all.Leases[0].ID != "a" {
		t.Fatalf("default now/max limit/tie sort result = %+v", all)
	}
	pastEnd := List(input, ListOptions{Cursor: "200", Limit: 1, Now: now})
	if len(pastEnd.Leases) != 0 {
		t.Fatalf("past-end list = %+v", pastEnd)
	}
	if start := cursorStart(input, "2"); start != 2 {
		t.Fatalf("numeric cursor start = %d", start)
	}
	if start := cursorStart(input, "bad|a"); start != 0 {
		t.Fatalf("bad stable cursor start = %d", start)
	}
}
