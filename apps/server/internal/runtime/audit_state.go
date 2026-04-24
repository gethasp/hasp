package runtime

import (
	"sync"
	"time"
)

type AuditState struct {
	mu         sync.RWMutex
	degradedAt *time.Time
	now        func() time.Time
}

func newAuditState(now func() time.Time) *AuditState {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &AuditState{now: now}
}

func (s *AuditState) RecordAppendResult(err error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.degradedAt = nil
		return
	}
	if s.degradedAt != nil {
		return
	}
	when := s.now().UTC()
	s.degradedAt = &when
}

func (s *AuditState) MarkDegradedAt(when time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	degraded := when.UTC()
	s.degradedAt = &degraded
}

func (s *AuditState) Snapshot() (bool, *time.Time) {
	if s == nil {
		return false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.degradedAt == nil {
		return false, nil
	}
	degraded := *s.degradedAt
	return true, &degraded
}
