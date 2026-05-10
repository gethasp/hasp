package runtime

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/approvals"
)

type ApprovalStore struct {
	mu        sync.RWMutex
	approvals map[string]approvals.Approval
	now       func() time.Time
	onQueue   func(approvals.Approval)
}

type QueueApprovalInput struct {
	SecretID            string
	RequesterConsumerID string
	RequesterVerifier   string
	RequestedScope      string
	RequestedTTLS       int
	TTL                 time.Duration
}

func NewApprovalStore() *ApprovalStore {
	return &ApprovalStore{
		approvals: make(map[string]approvals.Approval),
		now:       func() time.Time { return time.Now().UTC() },
	}
}

func (s *ApprovalStore) Queue(input QueueApprovalInput) (approvals.Approval, error) {
	secretID := strings.TrimSpace(input.SecretID)
	consumerID := strings.TrimSpace(input.RequesterConsumerID)
	if secretID == "" {
		return approvals.Approval{}, errors.New("secret_id is required")
	}
	if consumerID == "" {
		return approvals.Approval{}, errors.New("requester_consumer_id is required")
	}
	scope := strings.TrimSpace(input.RequestedScope)
	if scope == "" {
		scope = "session"
	}
	if input.RequestedTTLS <= 0 {
		input.RequestedTTLS = int(DefaultSessionTTL.Seconds())
	}
	if input.TTL <= 0 {
		input.TTL = 5 * time.Minute
	}
	id, err := randomHex(10)
	if err != nil {
		return approvals.Approval{}, fmt.Errorf("mint approval id: %w", err)
	}
	now := s.now().UTC()
	approval := approvals.Approval{
		ID:                  id,
		SecretID:            secretID,
		RequesterConsumerID: consumerID,
		RequesterVerifier:   strings.TrimSpace(input.RequesterVerifier),
		RequestedScope:      scope,
		RequestedTTLS:       input.RequestedTTLS,
		RequestedAt:         now,
		ExpiresAt:           now.Add(input.TTL),
		Status:              "pending",
	}
	if approval.RequesterVerifier == "" {
		approval.RequesterVerifier = "local-daemon-peer"
	}
	s.mu.Lock()
	s.approvals[approval.ID] = approval
	onQueue := s.onQueue
	s.mu.Unlock()
	if onQueue != nil {
		onQueue(approval)
	}
	return approval, nil
}

func (s *ApprovalStore) SetOnQueue(fn func(approvals.Approval)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onQueue = fn
}

func (s *ApprovalStore) Snapshot() []approvals.Approval {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]approvals.Approval, 0, len(s.approvals))
	for id, approval := range s.approvals {
		if approval.Status == "pending" && now.After(approval.ExpiresAt) {
			approval.Status = "expired"
			s.approvals[id] = approval
		}
		out = append(out, approval)
	}
	return out
}

func (s *ApprovalStore) Decide(id string, decision approvals.Decision, actor string, grant bool) (approvals.Approval, bool, error) {
	return s.DecidePrepared(id, &decision, actor, grant)
}

func (s *ApprovalStore) PrepareDecision(id string) (approvals.Approval, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return approvals.Approval{}, errors.New("approval_id is required")
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	approval, ok := s.approvals[id]
	if !ok {
		return approvals.Approval{}, errors.New("approval not found")
	}
	if approval.Status == "pending" && now.After(approval.ExpiresAt) {
		approval.Status = "expired"
		s.approvals[id] = approval
		return approval, errors.New("approval expired")
	}
	if approval.Status != "pending" {
		return approval, nil
	}
	return approval, nil
}

func (s *ApprovalStore) DecidePrepared(id string, decision *approvals.Decision, actor string, grant bool) (approvals.Approval, bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return approvals.Approval{}, false, errors.New("approval_id is required")
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	approval, ok := s.approvals[id]
	if !ok {
		return approvals.Approval{}, false, errors.New("approval not found")
	}
	if approval.Status == "pending" && now.After(approval.ExpiresAt) {
		approval.Status = "expired"
		s.approvals[id] = approval
		return approval, false, errors.New("approval expired")
	}
	if approval.Status != "pending" {
		return approval, false, nil
	}
	if strings.TrimSpace(actor) == "" {
		actor = "cli"
	}
	approval.Decision = decision
	approval.DecidedByActor = actor
	approval.DecidedAt = now
	if grant {
		approval.Status = "granted"
	} else {
		approval.Status = "denied"
	}
	s.approvals[id] = approval
	return approval, true, nil
}
