package dashboard

import "time"

type Vault struct {
	State          string     `json:"state"`
	LastUnlockedAt *time.Time `json:"last_unlocked_at,omitempty"`
	IdleRelockInS  int        `json:"idle_relock_in_s"`
}

type Leases struct {
	ActiveCount  int `json:"active_count"`
	ExpiringSoon int `json:"expiring_soon"`
}

type Approvals struct {
	PendingCount int `json:"pending_count"`
	OldestAgeS   int `json:"oldest_age_s"`
}

type Audit struct {
	ChainOK        bool       `json:"chain_ok"`
	LastVerifiedAt *time.Time `json:"last_verified_at,omitempty"`
}

type Integrations struct {
	OKCount       int  `json:"ok_count"`
	DegradedCount int  `json:"degraded_count"`
	Known         bool `json:"known"`
}

type Daemon struct {
	UptimeS      int          `json:"uptime_s"`
	Version      string       `json:"version"`
	HTTPListener HTTPListener `json:"http_listener"`
}

type HTTPListener struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type Session struct {
	OpenedAt   time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

type Input struct {
	Now                 time.Time
	StartedAt           time.Time
	Sessions            []Session
	VisibleSessions     []Session
	IdleTTL             time.Duration
	AuditDegraded       bool
	AuditDegradedAt     *time.Time
	PendingApprovals    int
	OldestApprovalS     int
	OKIntegrations      int
	BadIntegrations     int
	IntegrationsKnown   bool
	Version             string
	HTTPListener        HTTPListener
	AuditLastVerifiedAt *time.Time
}

type Payload struct {
	Vault        Vault        `json:"vault"`
	Leases       Leases       `json:"leases"`
	Approvals    Approvals    `json:"approvals"`
	Audit        Audit        `json:"audit"`
	Integrations Integrations `json:"integrations"`
	Daemon       Daemon       `json:"daemon"`
}

type Response struct {
	Schema int `json:"_schema"`
	Payload
}

func Build(input Input) Payload {
	now := input.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	visibleSessions := input.VisibleSessions
	if visibleSessions == nil {
		visibleSessions = input.Sessions
	}
	expiringSoon := 0
	var lastUnlockedAt *time.Time
	idleRelockInS := 0
	expiryWindow := now.Add(30 * time.Minute)
	for _, session := range visibleSessions {
		expiresAt := session.ExpiresAt.UTC()
		if expiresAt.After(now) && !expiresAt.After(expiryWindow) {
			expiringSoon++
		}
	}
	for _, session := range input.Sessions {
		expiresAt := session.ExpiresAt.UTC()
		if !expiresAt.After(now) {
			continue
		}
		openedAt := session.OpenedAt.UTC()
		if lastUnlockedAt == nil || openedAt.After(*lastUnlockedAt) {
			lastUnlockedAt = &openedAt
		}
		idleDeadline := session.LastSeenAt.UTC().Add(input.IdleTTL)
		remaining := int(idleDeadline.Sub(now).Seconds())
		if remaining > 0 && (idleRelockInS == 0 || remaining < idleRelockInS) {
			idleRelockInS = remaining
		}
	}

	vaultState := "locked"
	if len(input.Sessions) > 0 {
		vaultState = "unlocked"
	}
	uptimeS := int(now.Sub(input.StartedAt.UTC()).Seconds())
	if uptimeS < 0 {
		uptimeS = 0
	}
	return Payload{
		Vault: Vault{
			State:          vaultState,
			LastUnlockedAt: lastUnlockedAt,
			IdleRelockInS:  idleRelockInS,
		},
		Leases: Leases{
			ActiveCount:  len(visibleSessions),
			ExpiringSoon: expiringSoon,
		},
		Approvals: Approvals{
			PendingCount: input.PendingApprovals,
			OldestAgeS:   input.OldestApprovalS,
		},
		Audit: Audit{
			ChainOK:        !input.AuditDegraded,
			LastVerifiedAt: input.AuditLastVerifiedAt,
		},
		Integrations: Integrations{
			OKCount:       input.OKIntegrations,
			DegradedCount: input.BadIntegrations,
			Known:         input.IntegrationsKnown,
		},
		Daemon: Daemon{
			UptimeS:      uptimeS,
			Version:      input.Version,
			HTTPListener: input.HTTPListener,
		},
	}
}
