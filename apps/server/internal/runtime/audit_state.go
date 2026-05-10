package runtime

import (
	"sync"
	"time"
)

type AuditState struct {
	mu               sync.RWMutex
	appendDegradedAt *time.Time
	verifyDegradedAt *time.Time
	lastVerifiedAt   *time.Time
	now              func() time.Time
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
		s.appendDegradedAt = nil
		return
	}
	if s.appendDegradedAt != nil {
		return
	}
	when := s.now().UTC()
	s.appendDegradedAt = &when
}

func (s *AuditState) MarkDegradedAt(when time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	degraded := when.UTC()
	s.appendDegradedAt = &degraded
}

func (s *AuditState) MarkVerifyFailedAt(when time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	degraded := when.UTC()
	s.verifyDegradedAt = &degraded
}

func (s *AuditState) MarkVerifiedAt(when time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	verified := when.UTC()
	s.lastVerifiedAt = &verified
	s.verifyDegradedAt = nil
}

func (s *AuditState) Snapshot() (bool, *time.Time) {
	if s == nil {
		return false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	degradedAt := earliestTime(s.appendDegradedAt, s.verifyDegradedAt)
	if degradedAt == nil {
		return false, nil
	}
	degraded := *degradedAt
	return true, &degraded
}

func (s *AuditState) LastVerifiedAt() *time.Time {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lastVerifiedAt == nil {
		return nil
	}
	verified := *s.lastVerifiedAt
	return &verified
}

func earliestTime(first *time.Time, second *time.Time) *time.Time {
	switch {
	case first == nil:
		return second
	case second == nil:
		return first
	case first.Before(*second):
		return first
	default:
		return second
	}
}
