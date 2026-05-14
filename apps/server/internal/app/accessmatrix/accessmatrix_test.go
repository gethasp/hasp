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
			ID: "lease-1", SecretID: "prod/expiring", ConsumerID: "ci-runner", GrantedAt: now.Add(-time.Minute),
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

func TestBuildEdgeBranchesAndHelpers(t *testing.T) {
	now := time.Date(2026, 5, 10, 8, 0, 0, 0, time.UTC)
	usedOld := now.Add(-2 * time.Minute)
	usedNew := now.Add(-30 * time.Second)
	input := Input{
		AppConsumers: []store.AppConsumer{
			{Name: "app", Bindings: []store.AppBinding{{SecretName: "missing"}, {SecretName: "api"}}},
			{Name: "  "},
		},
		AgentConsumers: []store.AgentConsumer{{Name: "agent"}, {Name: "  "}},
		Items: []store.Item{
			{ID: "api-id", Name: "api", UpdatedAt: now},
			{ID: "db-id", Name: "db", UpdatedAt: now.Add(-time.Hour)},
		},
		Sessions: []Session{
			{Token: "tok-agent", ConsumerID: "agent"},
			{Token: "", ConsumerID: "skip"},
			{Token: "tok-empty", ConsumerID: ""},
		},
		SecretGrants: []store.SecretGrant{
			{SessionToken: "tok-agent", ItemName: "db", Scope: store.GrantSession, UsedAt: &usedOld},
			{SessionToken: "missing-token", ItemName: "db", Scope: store.GrantSession, UsedAt: &usedOld},
			{SessionToken: "tok-agent", ItemName: "missing", Scope: store.GrantSession, UsedAt: &usedOld},
		},
		PlaintextGrants: []store.PlaintextGrant{
			{SessionToken: "tok-agent", ItemName: "api", Scope: store.GrantSession, Action: store.PlaintextReveal, UsedAt: &usedNew},
			{SessionToken: "tok-agent", ItemName: "missing", Scope: store.GrantSession},
		},
		MutationGrants: []store.MutationGrant{
			{SessionToken: "tok-agent", ItemName: "api", Scope: store.GrantSession, Action: store.SecretMutationExpose, UsedAt: &usedOld},
			{SessionToken: "tok-agent", ItemName: "missing", Scope: store.GrantSession},
		},
		Leases: []leases.Lease{
			{ID: "inactive", SecretID: "api", ConsumerID: "agent", LastUsedAt: now, Scope: "session", Status: "revoked"},
			{ID: "nameref", SecretID: "api", ConsumerID: "agent", LastUsedAt: now, ExpiresAt: now.Add(2 * time.Hour), Scope: "session", Status: "active"},
			{ID: "idref", SecretID: "db-id", ConsumerID: "agent", LastUsedAt: now.Add(-time.Second), ExpiresAt: now.Add(2 * time.Hour), Scope: "window", Status: "active"},
			{ID: "badsecret", SecretID: "missing", ConsumerID: "agent", LastUsedAt: now, Scope: "session", Status: "active"},
			{ID: "badconsumer", SecretID: "api", ConsumerID: " ", LastUsedAt: now, Scope: "session", Status: "active"},
		},
		Approvals: []approvals.Approval{
			{ID: "skip-status", SecretID: "api", RequesterConsumerID: "agent", Status: "granted", RequestedAt: now},
			{ID: "skip-secret", SecretID: "missing", RequesterConsumerID: "agent", Status: "pending", RequestedAt: now},
			{ID: "skip-consumer", SecretID: "api-id", RequesterConsumerID: "", Status: "pending", RequestedAt: now},
			{ID: "newer", SecretID: "api-id", RequesterConsumerID: "agent", Status: "pending", RequestedAt: now},
			{ID: "older", SecretID: "api-id", RequesterConsumerID: "agent", Status: "pending", RequestedAt: now.Add(-time.Minute)},
		},
		AuditEvents: []audit.Event{
			{Sequence: 1, Timestamp: now.Add(-25 * time.Hour), Type: audit.EventRead, Details: map[string]any{"consumer_id": "agent", "secret_id": "db-id"}},
			{Sequence: 2, Timestamp: now.Add(-time.Hour), Type: audit.EventRead, Details: map[string]any{"consumer_name": "agent", "item_name": "db"}},
			{Sequence: 1, Timestamp: now.Add(-30 * time.Minute), Type: audit.EventRead, Details: map[string]any{"consumer_id": "agent", "secret_id": "db-id", "outcome": "denied"}},
			{Sequence: 3, Timestamp: now.Add(-10 * time.Minute), Type: audit.EventRead, Details: map[string]any{"actor": "agent", "secret": "missing"}},
			{Sequence: 4, Timestamp: now.Add(-5 * time.Minute), Type: audit.EventRead, Details: map[string]any{"actor": "", "secret": "api"}},
		},
		Now: now,
	}
	if _, err := Build(input, Options{Source: "bad"}); err == nil {
		t.Fatal("invalid source should fail")
	}
	if _, err := Build(input, Options{Cursor: "bad"}); err == nil {
		t.Fatal("invalid cursor should fail")
	}
	if _, err := Build(input, Options{Cursor: "-1"}); err == nil {
		t.Fatal("negative cursor should fail")
	}
	reply, err := Build(input, Options{Range: "ALL-TIME", Consumer: "agent", Secret: "db-id", Scope: "window", Source: "manual", HasActiveLease: boolPtr(true), Cursor: "200", Limit: -1})
	if err != nil {
		t.Fatalf("build filtered edge matrix: %v", err)
	}
	if reply.Range != "all-time" || reply.Total == 0 || len(reply.Grants) != 0 {
		t.Fatalf("cursor past end reply = %+v", reply)
	}
	noActive, err := Build(input, Options{HasActiveLease: boolPtr(false), Limit: 100})
	if err != nil {
		t.Fatalf("build inactive filter: %v", err)
	}
	if noActive.Total == 0 {
		t.Fatalf("inactive filter should retain policy-only grants: %+v", noActive)
	}
	if normalizeRange("unknown") != "live" || durationText(-time.Second) != "0s" || durationText(90*time.Minute) != "1h" {
		t.Fatal("range or duration edge cases failed")
	}
}

func TestResidualHelperBranches(t *testing.T) {
	now := time.Date(2026, 5, 10, 8, 0, 0, 0, time.UTC)
	_, _, secrets := indexSecrets([]store.Item{
		{ID: "b", Name: "same", UpdatedAt: now},
		{ID: "a", Name: "same", UpdatedAt: now},
	})
	if len(secrets) != 2 || secrets[0].ID != "a" {
		t.Fatalf("secret tie sort = %+v", secrets)
	}
	consumers := collectConsumers(Input{
		Leases: []leases.Lease{
			{ConsumerID: "lease-consumer"},
			{ConsumerID: "app"},
		},
		AppConsumers: []store.AppConsumer{{Name: "app"}},
	}, "")
	if len(consumers) != 2 || consumers[0].ID != "app" || consumers[1].ID != "lease-consumer" {
		t.Fatalf("lease consumers = %+v", consumers)
	}
	emptySecret := map[string]Secret{"": {ID: "", Path: ""}}
	counts, _ := indexActiveLeases([]leases.Lease{{Status: "active", SecretID: "", ConsumerID: ""}}, nil, emptySecret)
	if len(counts) != 0 {
		t.Fatalf("empty active lease key should be skipped: %+v", counts)
	}
	if matchesGrant(Grant{Source: "policy"}, Options{Source: "manual"}, nil) {
		t.Fatal("source mismatch should not match")
	}
	cells := projectCells(Input{Now: time.Time{}}, "live", []Consumer{{ID: "consumer"}}, []Secret{{ID: "secret", Path: "secret"}}, nil)
	if len(cells) != 1 || cells[0].State != "never" {
		t.Fatalf("zero-time cells = %+v", cells)
	}
	pending := pendingApprovalsByCell([]approvals.Approval{{Status: "pending", SecretID: "", RequesterConsumerID: ""}}, emptySecret)
	if len(pending) != 0 {
		t.Fatalf("empty pending key should be skipped: %+v", pending)
	}
	oldAudit := latestAuditByCell([]audit.Event{{Sequence: 1, Timestamp: now.Add(-25 * time.Hour), Details: map[string]any{"consumer_id": "consumer", "secret_id": "secret"}}}, map[string]Secret{"secret": {ID: "secret", Path: "secret"}}, now, "24h")
	if len(oldAudit) != 0 {
		t.Fatalf("old audit should be skipped: %+v", oldAudit)
	}
	latest := latestAuditByCell([]audit.Event{
		{Sequence: 2, Timestamp: now, Details: map[string]any{"consumer_id": "consumer", "secret_id": "secret"}},
		{Sequence: 1, Timestamp: now.Add(time.Minute), Details: map[string]any{"consumer_id": "consumer", "secret_id": "secret"}},
	}, map[string]Secret{"secret": {ID: "secret", Path: "secret"}}, now, "all-time")
	if latest["consumer\x00secret"].AuditSeq != 2 {
		t.Fatalf("latest audit map = %+v", latest)
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
