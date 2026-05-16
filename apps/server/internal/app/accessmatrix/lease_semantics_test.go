package accessmatrix

import (
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/approvals"
	"github.com/gethasp/hasp/apps/server/internal/leases"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestBuildMarksCellExpiringWhenLeaseReferencesSecretByName(t *testing.T) {
	reply, err := Build(accessMatrixLeaseInput([]leases.Lease{{
		ID:         "lease-name",
		SecretID:   "API_TOKEN",
		ConsumerID: "ci-runner",
		Scope:      "session",
		Status:     "active",
		LastUsedAt: leaseNow().Add(-time.Second),
		ExpiresAt:  leaseNow().Add(30 * time.Second),
	}}), Options{Range: "live", Limit: 10})
	if err != nil {
		t.Fatalf("build matrix: %v", err)
	}
	if got := stateFor(reply.Cells, "secret-api"); got != "expiring" {
		t.Fatalf("cell state=%q, want expiring", got)
	}
}

func TestBuildMarksCellExpiringWhenLeaseReferencesSecretByID(t *testing.T) {
	reply, err := Build(accessMatrixLeaseInput([]leases.Lease{{
		ID:         "lease-id",
		SecretID:   "secret-api",
		ConsumerID: "ci-runner",
		Scope:      "session",
		Status:     "active",
		LastUsedAt: leaseNow().Add(-time.Second),
		ExpiresAt:  leaseNow().Add(45 * time.Second),
	}}), Options{Range: "live", Limit: 10})
	if err != nil {
		t.Fatalf("build matrix: %v", err)
	}
	if got := stateFor(reply.Cells, "secret-api"); got != "expiring" {
		t.Fatalf("cell state=%q, want expiring", got)
	}
}

func TestBuildKeepsPendingApprovalAheadOfExpiringLease(t *testing.T) {
	now := leaseNow()
	reply, err := Build(Input{
		AppConsumers: []store.AppConsumer{{Name: "ci-runner"}},
		Items:        []store.Item{{ID: "secret-api", Name: "API_TOKEN", UpdatedAt: now}},
		Leases: []leases.Lease{{
			ID:         "lease-expiring",
			SecretID:   "API_TOKEN",
			ConsumerID: "ci-runner",
			Scope:      "session",
			Status:     "active",
			LastUsedAt: now.Add(-time.Second),
			ExpiresAt:  now.Add(30 * time.Second),
		}},
		Approvals: []approvals.Approval{{
			ID:                  "approval-1",
			SecretID:            "secret-api",
			RequesterConsumerID: "ci-runner",
			RequestedScope:      "window",
			RequestedAt:         now.Add(-15 * time.Second),
			Status:              "pending",
		}},
		Now: now,
	}, Options{Range: "live", Limit: 10})
	if err != nil {
		t.Fatalf("build matrix: %v", err)
	}
	if got := stateFor(reply.Cells, "secret-api"); got != "pending" {
		t.Fatalf("cell state=%q, want pending", got)
	}
}

func TestBuildDoesNotMarkExpiredLeaseAsExpiring(t *testing.T) {
	reply, err := Build(accessMatrixLeaseInput([]leases.Lease{{
		ID:         "lease-expired",
		SecretID:   "API_TOKEN",
		ConsumerID: "ci-runner",
		Scope:      "session",
		Status:     "active",
		LastUsedAt: leaseNow().Add(-time.Second),
		ExpiresAt:  leaseNow().Add(-time.Second),
	}}), Options{Range: "live", Limit: 10})
	if err != nil {
		t.Fatalf("build matrix: %v", err)
	}
	if got := stateFor(reply.Cells, "secret-api"); got != "session" {
		t.Fatalf("cell state=%q, want session", got)
	}
}

func TestBuildDoesNotMarkLeaseExpiringExactlyNowAsExpiring(t *testing.T) {
	reply, err := Build(accessMatrixLeaseInput([]leases.Lease{{
		ID:         "lease-now",
		SecretID:   "API_TOKEN",
		ConsumerID: "ci-runner",
		Scope:      "session",
		Status:     "active",
		LastUsedAt: leaseNow().Add(-time.Second),
		ExpiresAt:  leaseNow(),
	}}), Options{Range: "live", Limit: 10})
	if err != nil {
		t.Fatalf("build matrix: %v", err)
	}
	if got := stateFor(reply.Cells, "secret-api"); got != "session" {
		t.Fatalf("cell state=%q, want session", got)
	}
}

func TestBuildDoesNotMarkLeaseExpiringInExactlyOneMinuteAsExpiring(t *testing.T) {
	reply, err := Build(accessMatrixLeaseInput([]leases.Lease{{
		ID:         "lease-minute",
		SecretID:   "API_TOKEN",
		ConsumerID: "ci-runner",
		Scope:      "session",
		Status:     "active",
		LastUsedAt: leaseNow().Add(-time.Second),
		ExpiresAt:  leaseNow().Add(time.Minute),
	}}), Options{Range: "live", Limit: 10})
	if err != nil {
		t.Fatalf("build matrix: %v", err)
	}
	if got := stateFor(reply.Cells, "secret-api"); got != "session" {
		t.Fatalf("cell state=%q, want session", got)
	}
}

func TestBuildTrimsLeaseConsumerIDsAndStatusesBeforeDetectingExpiringLease(t *testing.T) {
	reply, err := Build(accessMatrixLeaseInput([]leases.Lease{{
		ID:         "lease-trimmed",
		SecretID:   "API_TOKEN",
		ConsumerID: " ci-runner ",
		Scope:      "session",
		Status:     " active ",
		LastUsedAt: leaseNow().Add(-time.Second),
		ExpiresAt:  leaseNow().Add(20 * time.Second),
	}}), Options{Range: "live", Limit: 10})
	if err != nil {
		t.Fatalf("build matrix: %v", err)
	}
	if got := stateFor(reply.Cells, "secret-api"); got != "expiring" {
		t.Fatalf("cell state=%q, want expiring", got)
	}
}

func TestBuildScopesCellsToFilteredSecretSet(t *testing.T) {
	now := leaseNow()
	reply, err := Build(Input{
		AppConsumers: []store.AppConsumer{{Name: "ci-runner"}},
		Items: []store.Item{
			{ID: "secret-api", Name: "API_TOKEN", UpdatedAt: now},
			{ID: "secret-db", Name: "DATABASE_URL", UpdatedAt: now},
		},
		Leases: []leases.Lease{{
			ID:         "lease-api",
			SecretID:   "API_TOKEN",
			ConsumerID: "ci-runner",
			Scope:      "session",
			Status:     "active",
			LastUsedAt: now.Add(-time.Second),
			ExpiresAt:  now.Add(30 * time.Second),
		}},
		Now: now,
	}, Options{Range: "live", Secret: "DATABASE_URL", Limit: 10})
	if err != nil {
		t.Fatalf("build matrix: %v", err)
	}
	if len(reply.Secrets) != 1 || reply.Secrets[0].ID != "secret-db" {
		t.Fatalf("filtered secrets=%+v, want DATABASE_URL only", reply.Secrets)
	}
	if len(reply.Cells) != 1 || reply.Cells[0].SecretID != "secret-db" {
		t.Fatalf("filtered cells=%+v, want DATABASE_URL only", reply.Cells)
	}
}

func accessMatrixLeaseInput(leasesInput []leases.Lease) Input {
	now := leaseNow()
	return Input{
		AppConsumers: []store.AppConsumer{{Name: "ci-runner"}},
		Items:        []store.Item{{ID: "secret-api", Name: "API_TOKEN", UpdatedAt: now}},
		Leases:       leasesInput,
		Now:          now,
	}
}

func leaseNow() time.Time {
	return time.Date(2026, 5, 10, 8, 0, 0, 0, time.UTC)
}
