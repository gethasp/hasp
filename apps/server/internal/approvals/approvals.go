package approvals

import (
	"sort"
	"strings"
	"time"
)

type Decision struct {
	GrantedTTLS int    `json:"granted_ttl_s,omitempty"`
	Scope       string `json:"scope,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type Approval struct {
	ID                  string    `json:"id"`
	SecretID            string    `json:"secret_id"`
	RequesterConsumerID string    `json:"requester_consumer_id"`
	RequesterVerifier   string    `json:"requester_verifier,omitempty"`
	RequestedScope      string    `json:"requested_scope"`
	RequestedTTLS       int       `json:"requested_ttl_s"`
	RequestedAt         time.Time `json:"requested_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Status              string    `json:"status"`
	Decision            *Decision `json:"decision,omitempty"`
	DecidedByActor      string    `json:"decided_by_actor,omitempty"`
	DecidedAt           time.Time `json:"decided_at,omitempty"`
}

type ListOptions struct {
	Status     string
	ConsumerID string
	Now        time.Time
}

type Response struct {
	Approvals         []Approval `json:"approvals"`
	PendingCount      int        `json:"pending_count"`
	OldestPendingAgeS int        `json:"oldest_pending_age_s"`
}

func List(input []Approval, opts ListOptions) Response {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	status := strings.TrimSpace(opts.Status)
	consumer := strings.TrimSpace(opts.ConsumerID)
	out := make([]Approval, 0, len(input))
	pendingCount := 0
	oldestAge := 0
	for _, approval := range input {
		approval = normalizeExpired(approval, now)
		if approval.Status == "pending" {
			pendingCount++
			age := int(now.Sub(approval.RequestedAt).Seconds())
			if age > oldestAge {
				oldestAge = age
			}
		}
		if status != "" && approval.Status != status {
			continue
		}
		if consumer != "" && approval.RequesterConsumerID != consumer {
			continue
		}
		out = append(out, approval)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Status == "pending" && out[j].Status != "pending" {
			return true
		}
		if out[i].Status != "pending" && out[j].Status == "pending" {
			return false
		}
		if out[i].RequestedAt.Equal(out[j].RequestedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].RequestedAt.Before(out[j].RequestedAt)
	})
	return Response{Approvals: out, PendingCount: pendingCount, OldestPendingAgeS: oldestAge}
}

func normalizeExpired(approval Approval, now time.Time) Approval {
	if approval.Status == "pending" && !approval.ExpiresAt.IsZero() && now.After(approval.ExpiresAt) {
		approval.Status = "expired"
	}
	return approval
}
