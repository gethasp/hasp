package accessmatrix

import (
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/approvals"
	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/leases"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestBuildFiltersPaginatesAndSkipsSyntheticLeaseSecrets(t *testing.T) {
	now := time.Date(2026, 5, 10, 8, 0, 0, 0, time.UTC)
	usedAt := now.Add(-time.Minute)
	input := Input{
		AppConsumers: []store.AppConsumer{{
			Name:     "ci-runner",
			Bindings: []store.AppBinding{{SecretName: "OPENAI_API_KEY"}},
		}},
		Items: []store.Item{
			{ID: "sec_api", Name: "OPENAI_API_KEY", UpdatedAt: now.Add(-time.Hour)},
			{ID: "sec_db", Name: "DATABASE_URL", UpdatedAt: now.Add(-2 * time.Hour)},
		},
		SecretGrants: []store.SecretGrant{{
			SessionToken: "tok_ci",
			ItemName:     "DATABASE_URL",
			Scope:        store.GrantSession,
			UsedAt:       &usedAt,
		}},
		Sessions: []Session{{Token: "tok_ci", ConsumerID: "ci-runner"}},
		Leases: []leases.Lease{
			{ID: "lease-1", SecretID: "DATABASE_URL", ConsumerID: "ci-runner", LastUsedAt: now, Scope: "session", Status: "active"},
			{ID: "lease-2", SecretID: "/tmp/project-root", ConsumerID: "ci-runner", LastUsedAt: now, Scope: "project", Status: "active"},
		},
		Now: now,
	}
	reply, err := Build(input, Options{Consumer: "ci-runner", Limit: 1})
	if err != nil {
		t.Fatalf("build matrix: %v", err)
	}
	if reply.Total != 2 || len(reply.Grants) != 1 || !reply.HasMore || reply.NextCursor == "" {
		t.Fatalf("first page = %+v, want one of two grants with cursor", reply)
	}
	next, err := Build(input, Options{Consumer: "ci-runner", Cursor: reply.NextCursor, Limit: 1})
	if err != nil {
		t.Fatalf("build second page: %v", err)
	}
	seen := map[string]bool{
		reply.Grants[0].SecretID + "/" + reply.Grants[0].Source: true,
		next.Grants[0].SecretID + "/" + next.Grants[0].Source:   true,
	}
	if !seen["sec_api/policy"] || !seen["sec_db/manual"] || next.HasMore {
		t.Fatalf("paged grants = first %+v second %+v", reply.Grants, next.Grants)
	}
	filtered, err := Build(input, Options{Secret: "DATABASE_URL", HasActiveLease: boolPtr(true)})
	if err != nil {
		t.Fatalf("build active lease filter: %v", err)
	}
	if filtered.Total != 1 || filtered.Grants[0].SecretID != "sec_db" || filtered.Grants[0].LeaseCount != 1 {
		t.Fatalf("active filtered matrix = %+v", filtered)
	}
}

func TestBuildCapsLimitAtMatrixSurfaceSize(t *testing.T) {
	now := time.Date(2026, 5, 10, 8, 0, 0, 0, time.UTC)
	items := make([]store.Item, 0, MaxLimit+1)
	bindings := make([]store.AppBinding, 0, MaxLimit+1)
	for i := 0; i < MaxLimit+1; i++ {
		name := "SECRET_" + time.Unix(int64(i), 0).UTC().Format("150405")
		items = append(items, store.Item{ID: name, Name: name, UpdatedAt: now})
		bindings = append(bindings, store.AppBinding{SecretName: name})
	}
	reply, err := Build(Input{
		AppConsumers: []store.AppConsumer{{Name: "ci-runner", Bindings: bindings}},
		Items:        items,
		Now:          now,
	}, Options{Consumer: "ci-runner", Limit: MaxLimit + 500})
	if err != nil {
		t.Fatalf("build matrix: %v", err)
	}
	if reply.Total != MaxLimit+1 || len(reply.Grants) != MaxLimit || !reply.HasMore {
		t.Fatalf("capped reply total=%d grants=%d hasMore=%v, want total %d grants %d hasMore true", reply.Total, len(reply.Grants), reply.HasMore, MaxLimit+1, MaxLimit)
	}
}

func TestBuildProjectsCanonicalCellStatesByPrecedenceAndRange(t *testing.T) {
	now := time.Date(2026, 5, 10, 8, 0, 0, 0, time.UTC)
	input := Input{
		AppConsumers: []store.AppConsumer{{Name: "ci-runner"}},
		Items: []store.Item{
			{ID: "pending", Name: "prod/pending", UpdatedAt: now},
			{ID: "expiring", Name: "prod/expiring", UpdatedAt: now},
			{ID: "past", Name: "prod/past", UpdatedAt: now},
			{ID: "denied", Name: "prod/denied", UpdatedAt: now},
			{ID: "never", Name: "prod/never", UpdatedAt: now},
		},
		Approvals: []approvals.Approval{{
			ID: "approval-1", SecretID: "pending", RequesterConsumerID: "ci-runner",
			RequestedScope: "window", RequestedAt: now.Add(-30 * time.Second), ExpiresAt: now.Add(time.Minute), Status: "pending",
		}},
		Leases: []leases.Lease{{
			ID: "lease-1", SecretID: "expiring", ConsumerID: "ci-runner", GrantedAt: now.Add(-time.Minute),
			ExpiresAt: now.Add(30 * time.Second), LastUsedAt: now.Add(-time.Second), Scope: "window", Status: "active",
		}},
		AuditEvents: []audit.Event{
			{Sequence: 1, Timestamp: now.Add(-2 * time.Hour), Type: audit.EventRead, Details: map[string]any{"consumer_id": "ci-runner", "secret_id": "past"}},
			{Sequence: 2, Timestamp: now.Add(-time.Hour), Type: audit.EventDeny, Details: map[string]any{"consumer_id": "ci-runner", "secret_id": "denied"}},
		},
		Now: now,
	}
	live, err := Build(input, Options{Range: "live", Limit: 100})
	if err != nil {
		t.Fatalf("build live matrix: %v", err)
	}
	if stateFor(live.Cells, "pending") != "pending" || stateFor(live.Cells, "expiring") != "expiring" || stateFor(live.Cells, "past") != "never" {
		t.Fatalf("live cells = %+v", live.Cells)
	}
	history, err := Build(input, Options{Range: "24h", Limit: 100})
	if err != nil {
		t.Fatalf("build history matrix: %v", err)
	}
	if stateFor(history.Cells, "past") != "past" || stateFor(history.Cells, "denied") != "denied" || stateFor(history.Cells, "never") != "never" {
		t.Fatalf("history cells = %+v", history.Cells)
	}
}

func stateFor(cells []Cell, secretID string) string {
	for _, cell := range cells {
		if cell.SecretID == secretID {
			return cell.State
		}
	}
	return ""
}

func boolPtr(value bool) *bool {
	return &value
}
