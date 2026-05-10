package store

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

var (
	ErrPolicyVersionConflict = errors.New("policy version conflict")
	ErrPolicyInvalid         = errors.New("policy invalid")
)

type PolicyDocument struct {
	Version   string       `json:"version"`
	Rules     []PolicyRule `json:"rules"`
	UpdatedAt time.Time    `json:"updated_at"`
	UpdatedBy string       `json:"updated_by"`
}

type PolicyRule struct {
	ID            string      `json:"id"`
	Match         PolicyMatch `json:"match"`
	Decision      string      `json:"decision"`
	TTLS          int         `json:"ttl_s,omitempty"`
	MaxConcurrent int         `json:"max_concurrent,omitempty"`
	Priority      int         `json:"priority,omitempty"`
}

type PolicyMatch struct {
	Consumer string `json:"consumer"`
	Secret   string `json:"secret"`
	Scope    string `json:"scope"`
}

func (h *Handle) GetPolicy() PolicyDocument {
	return normalizePolicyDocument(h.state.Policy)
}

func (h *Handle) ReplacePolicy(next PolicyDocument, expectedVersion string, force bool, updatedBy string) (PolicyDocument, error) {
	unlock := lockVaultStatePath(h.store.paths.StatePath)
	defer unlock()
	envelope, err := h.store.readEnvelopeStrict()
	if err != nil {
		return PolicyDocument{}, err
	}
	latest, err := readState(h.vaultKey, envelope.Data)
	if err != nil {
		return PolicyDocument{}, err
	}
	h.state = latest
	current := h.GetPolicy()
	if !force && strings.TrimSpace(expectedVersion) != current.Version {
		return PolicyDocument{}, fmt.Errorf("%w: expected %q got %q", ErrPolicyVersionConflict, expectedVersion, current.Version)
	}
	next.Version = ""
	next.UpdatedAt = time.Time{}
	next.UpdatedBy = ""
	if err := ValidatePolicy(next); err != nil {
		return PolicyDocument{}, err
	}
	version, err := randomHex(12)
	if err != nil {
		return PolicyDocument{}, fmt.Errorf("mint policy version: %w", err)
	}
	now := h.store.now().UTC()
	next = normalizePolicyDocument(next)
	next.Version = version
	next.UpdatedAt = now
	next.UpdatedBy = strings.TrimSpace(updatedBy)
	if next.UpdatedBy == "" {
		next.UpdatedBy = "user"
	}
	h.state.Policy = next
	if err := h.persistUnlocked(); err != nil {
		return PolicyDocument{}, err
	}
	h.store.appendAuditBestEffort("policy.update", next.UpdatedBy, map[string]any{
		"version":    next.Version,
		"rule_count": len(next.Rules),
	})
	return next, nil
}

func ValidatePolicy(doc PolicyDocument) error {
	doc = normalizePolicyDocument(doc)
	seenIDs := make(map[string]struct{}, len(doc.Rules))
	seenMatch := make(map[string]PolicyRule, len(doc.Rules))
	for i, rule := range doc.Rules {
		if strings.TrimSpace(rule.ID) == "" {
			return fmt.Errorf("%w: rule %d id is required", ErrPolicyInvalid, i)
		}
		if _, ok := seenIDs[rule.ID]; ok {
			return fmt.Errorf("%w: duplicate rule id %q", ErrPolicyInvalid, rule.ID)
		}
		seenIDs[rule.ID] = struct{}{}
		if rule.Match.Consumer == "" || rule.Match.Secret == "" || rule.Match.Scope == "" {
			return fmt.Errorf("%w: rule %q match consumer, secret, and scope are required", ErrPolicyInvalid, rule.ID)
		}
		switch rule.Decision {
		case "allow", "deny", "require_approval":
		default:
			return fmt.Errorf("%w: rule %q has unsupported decision %q", ErrPolicyInvalid, rule.ID, rule.Decision)
		}
		if rule.TTLS < 0 {
			return fmt.Errorf("%w: rule %q ttl_s must be >= 0", ErrPolicyInvalid, rule.ID)
		}
		if rule.MaxConcurrent < 0 {
			return fmt.Errorf("%w: rule %q max_concurrent must be >= 0", ErrPolicyInvalid, rule.ID)
		}
		matchKey := strings.Join([]string{rule.Match.Consumer, rule.Match.Secret, rule.Match.Scope}, "\x00")
		if existing, ok := seenMatch[matchKey]; ok && existing.Decision != rule.Decision {
			return fmt.Errorf("%w: rule %q conflicts with %q for consumer=%q secret=%q scope=%q", ErrPolicyInvalid, rule.ID, existing.ID, rule.Match.Consumer, rule.Match.Secret, rule.Match.Scope)
		}
		seenMatch[matchKey] = rule
	}
	return nil
}

func normalizePolicyDocument(doc PolicyDocument) PolicyDocument {
	doc.Version = strings.TrimSpace(doc.Version)
	if doc.Version == "" {
		doc.Version = "0"
	}
	doc.UpdatedBy = strings.TrimSpace(doc.UpdatedBy)
	if doc.UpdatedBy == "" {
		doc.UpdatedBy = "system"
	}
	rules := slices.Clone(doc.Rules)
	for i := range rules {
		rules[i].ID = strings.TrimSpace(rules[i].ID)
		rules[i].Match.Consumer = strings.TrimSpace(rules[i].Match.Consumer)
		rules[i].Match.Secret = strings.TrimSpace(rules[i].Match.Secret)
		rules[i].Match.Scope = strings.TrimSpace(rules[i].Match.Scope)
		rules[i].Decision = strings.TrimSpace(rules[i].Decision)
	}
	doc.Rules = rules
	return doc
}
