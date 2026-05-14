package dashboard

import (
	"testing"
	"time"
)

func TestBuildDashboardPayload(t *testing.T) {
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	lastVerified := now.Add(-time.Minute)
	payload := Build(Input{
		Now:                 now,
		StartedAt:           now.Add(-10 * time.Second),
		Sessions:            []Session{{OpenedAt: now.Add(-time.Hour), LastSeenAt: now.Add(-30 * time.Second), ExpiresAt: now.Add(time.Hour)}},
		VisibleSessions:     []Session{{ExpiresAt: now.Add(10 * time.Minute)}, {ExpiresAt: now.Add(time.Hour)}},
		IdleTTL:             time.Minute,
		PendingApprovals:    2,
		OldestApprovalS:     30,
		AuditDegraded:       true,
		OKIntegrations:      1,
		BadIntegrations:     2,
		IntegrationsKnown:   true,
		Version:             "1.0.6",
		HTTPListener:        HTTPListener{Host: "127.0.0.1", Port: 4321},
		AuditLastVerifiedAt: &lastVerified,
	})
	if payload.Vault.State != "unlocked" || payload.Vault.LastUnlockedAt == nil || payload.Vault.IdleRelockInS != 30 {
		t.Fatalf("vault payload = %+v", payload.Vault)
	}
	if payload.Leases.ActiveCount != 2 || payload.Leases.ExpiringSoon != 1 {
		t.Fatalf("leases payload = %+v", payload.Leases)
	}
	if payload.Approvals.PendingCount != 2 || payload.Audit.ChainOK || !payload.Integrations.Known || payload.Daemon.UptimeS != 10 {
		t.Fatalf("payload = %+v", payload)
	}

	locked := Build(Input{Now: now, StartedAt: now.Add(time.Second)})
	if locked.Vault.State != "locked" || locked.Daemon.UptimeS != 0 {
		t.Fatalf("locked payload = %+v", locked)
	}

	expired := time.Now().UTC().Add(-time.Hour)
	defaultNow := Build(Input{
		StartedAt: expired,
		Sessions:  []Session{{OpenedAt: expired, LastSeenAt: expired, ExpiresAt: expired}},
	})
	if defaultNow.Vault.State != "unlocked" || defaultNow.Vault.LastUnlockedAt != nil {
		t.Fatalf("expired sessions should not unlock vault: %+v", defaultNow.Vault)
	}
}
