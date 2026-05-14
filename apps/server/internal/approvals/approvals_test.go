package approvals

import (
	"testing"
	"time"
)

func TestListFiltersSortsAndExpiresPendingApprovals(t *testing.T) {
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	input := []Approval{
		{ID: "z", RequesterConsumerID: "agent-b", RequestedAt: now.Add(-time.Minute), Status: "approved"},
		{ID: "b", RequesterConsumerID: "agent-a", RequestedAt: now.Add(-3 * time.Minute), ExpiresAt: now.Add(time.Minute), Status: "pending"},
		{ID: "a", RequesterConsumerID: "agent-a", RequestedAt: now.Add(-3 * time.Minute), ExpiresAt: now.Add(time.Minute), Status: "pending"},
		{ID: "expired", RequesterConsumerID: "agent-a", RequestedAt: now.Add(-5 * time.Minute), ExpiresAt: now.Add(-time.Second), Status: "pending"},
	}

	all := List(input, ListOptions{Now: now})
	if all.PendingCount != 2 || all.OldestPendingAgeS != 180 {
		t.Fatalf("pending summary = %+v", all)
	}
	if got := []string{all.Approvals[0].ID, all.Approvals[1].ID, all.Approvals[2].ID, all.Approvals[3].ID}; got[0] != "a" || got[1] != "b" || got[2] != "expired" || got[3] != "z" {
		t.Fatalf("unexpected sort order: %v", got)
	}
	if all.Approvals[2].Status != "expired" {
		t.Fatalf("expired approval status = %q", all.Approvals[2].Status)
	}

	filtered := List(input, ListOptions{Status: " pending ", ConsumerID: " agent-a ", Now: now})
	if len(filtered.Approvals) != 2 || filtered.Approvals[0].ID != "a" || filtered.Approvals[1].ID != "b" {
		t.Fatalf("filtered approvals = %+v", filtered.Approvals)
	}
}

func TestListApprovalsDefaultNowAndTieBranches(t *testing.T) {
	now := time.Now().UTC().Add(time.Minute)
	input := []Approval{
		{ID: "b", RequesterConsumerID: "agent", RequestedAt: now, Status: "denied"},
		{ID: "a", RequesterConsumerID: "agent", RequestedAt: now, Status: "denied"},
		{ID: "pending", RequesterConsumerID: "other", RequestedAt: now.Add(time.Second), Status: "pending"},
	}
	reply := List(input, ListOptions{ConsumerID: "agent"})
	if len(reply.Approvals) != 2 || reply.Approvals[0].ID != "a" || reply.Approvals[1].ID != "b" {
		t.Fatalf("tie sorted approvals = %+v", reply.Approvals)
	}
	filtered := List(input, ListOptions{Status: "pending", ConsumerID: "missing"})
	if len(filtered.Approvals) != 0 || filtered.PendingCount != 1 {
		t.Fatalf("filtered missing approvals = %+v", filtered)
	}
}
