package accessmatrix

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/approvals"
	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/jsonwire"
	"github.com/gethasp/hasp/apps/server/internal/leases"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

const (
	DefaultLimit = 100
	MaxLimit     = 10000
)

type Consumer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type Secret struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Version string `json:"version"`
}

type Grant struct {
	ConsumerID string `json:"consumer_id"`
	SecretID   string `json:"secret_id"`
	Scope      string `json:"scope"`
	Source     string `json:"source"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	LeaseCount int    `json:"lease_count"`
}

type Cell struct {
	ConsumerID string `json:"consumer_id"`
	SecretID   string `json:"secret_id"`
	State      string `json:"state"`
	Glyph      string `json:"glyph"`
	Label      string `json:"label"`
	SubText    string `json:"sub_text,omitempty"`
	Scope      string `json:"scope,omitempty"`
	Source     string `json:"source,omitempty"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	LeaseCount int    `json:"lease_count,omitempty"`
	ApprovalID string `json:"approval_id,omitempty"`
	AuditSeq   int64  `json:"audit_seq,omitempty"`
}

type Response struct {
	Schema     int        `json:"_schema"`
	Range      string     `json:"range,omitempty"`
	Consumers  []Consumer `json:"consumers"`
	Secrets    []Secret   `json:"secrets"`
	Grants     []Grant    `json:"grants"`
	Cells      []Cell     `json:"cells,omitempty"`
	Total      int        `json:"total"`
	HasMore    bool       `json:"has_more"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

type Options struct {
	Range          string
	Consumer       string
	Secret         string
	Scope          string
	Source         string
	HasActiveLease *bool
	Cursor         string
	Limit          int
}

type Input struct {
	AppConsumers    []store.AppConsumer
	AgentConsumers  []store.AgentConsumer
	Items           []store.Item
	ProjectLeases   []store.ProjectLease
	SecretGrants    []store.SecretGrant
	PlaintextGrants []store.PlaintextGrant
	MutationGrants  []store.MutationGrant
	Sessions        []Session
	Leases          []leases.Lease
	Approvals       []approvals.Approval
	AuditEvents     []audit.Event
	Now             time.Time
}

type Session struct {
	Token      string
	ConsumerID string
}

func Build(input Input, opts Options) (Response, error) {
	if opts.Source != "" && opts.Source != "policy" && opts.Source != "manual" {
		return Response{}, fmt.Errorf(`source must be "policy" or "manual"`)
	}
	matrixRange := normalizeRange(opts.Range)
	limit := opts.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	secretByName, secretByID, secrets := indexSecrets(input.Items)
	consumers := collectConsumers(input, opts.Consumer)
	tokenConsumers := indexSessions(input.Sessions)
	leaseCounts, leaseLastUsed := indexActiveLeases(input.Leases, secretByName, secretByID)
	grants := make(map[string]Grant)
	addGrant := func(consumerID, secretID, scope, source string, lastUsedAt *time.Time) {
		consumerID = strings.TrimSpace(consumerID)
		secretID = strings.TrimSpace(secretID)
		scope = strings.TrimSpace(scope)
		source = strings.TrimSpace(source)
		if consumerID == "" || secretID == "" || source == "" {
			return
		}
		key := consumerID + "\x00" + secretID + "\x00" + scope + "\x00" + source
		grant := grants[key]
		grant.ConsumerID = consumerID
		grant.SecretID = secretID
		grant.Scope = scope
		grant.Source = source
		if lastUsedAt != nil && (grant.LastUsedAt == "" || lastUsedAt.UTC().Format(time.RFC3339Nano) > grant.LastUsedAt) {
			grant.LastUsedAt = lastUsedAt.UTC().Format(time.RFC3339Nano)
		}
		if activeLast, ok := leaseLastUsed[consumerID+"\x00"+secretID]; ok && (grant.LastUsedAt == "" || activeLast.UTC().Format(time.RFC3339Nano) > grant.LastUsedAt) {
			grant.LastUsedAt = activeLast.UTC().Format(time.RFC3339Nano)
		}
		grant.LeaseCount = leaseCounts[consumerID+"\x00"+secretID]
		grants[key] = grant
	}
	for _, consumer := range input.AppConsumers {
		for _, binding := range consumer.Bindings {
			secret, ok := secretByName[strings.TrimSpace(binding.SecretName)]
			if !ok {
				continue
			}
			addGrant(consumer.Name, secret.ID, "read", "policy", nil)
		}
	}
	for _, grant := range input.SecretGrants {
		secret, ok := secretByName[strings.TrimSpace(grant.ItemName)]
		if !ok {
			continue
		}
		addGrant(tokenConsumers[grant.SessionToken], secret.ID, string(grant.Scope), "manual", grant.UsedAt)
	}
	for _, grant := range input.PlaintextGrants {
		secret, ok := secretByName[strings.TrimSpace(grant.ItemName)]
		if !ok {
			continue
		}
		scope := string(grant.Scope)
		if grant.Action != "" {
			scope = scope + ":" + string(grant.Action)
		}
		addGrant(tokenConsumers[grant.SessionToken], secret.ID, scope, "manual", grant.UsedAt)
	}
	for _, grant := range input.MutationGrants {
		secret, ok := secretByName[strings.TrimSpace(grant.ItemName)]
		if !ok {
			continue
		}
		scope := string(grant.Scope)
		if grant.Action != "" {
			scope = scope + ":" + string(grant.Action)
		}
		addGrant(tokenConsumers[grant.SessionToken], secret.ID, scope, "manual", grant.UsedAt)
	}
	for _, lease := range input.Leases {
		if strings.TrimSpace(lease.Status) != "active" {
			continue
		}
		secretID := resolveSecretID(lease.SecretID, secretByName, secretByID)
		if _, ok := secretByID[secretID]; !ok {
			continue
		}
		addGrant(lease.ConsumerID, secretID, lease.Scope, "manual", &lease.LastUsedAt)
	}
	out := make([]Grant, 0, len(grants))
	for _, grant := range grants {
		if !matchesGrant(grant, opts, secretByID) {
			continue
		}
		out = append(out, grant)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return grantSortKey(out[i]) < grantSortKey(out[j])
	})
	start, err := cursorStart(out, opts.Cursor)
	if err != nil {
		return Response{}, err
	}
	total := len(out)
	if start > total {
		start = total
	}
	end := start + limit
	hasMore := end < total
	if end > total {
		end = total
	}
	reply := Response{
		Schema:    jsonwire.SchemaVersion,
		Range:     matrixRange,
		Consumers: consumers,
		Secrets:   filterSecrets(secrets, opts.Secret),
		Grants:    out[start:end],
		Total:     total,
		HasMore:   hasMore,
	}
	reply.Cells = projectCells(input, matrixRange, consumers, reply.Secrets, grants)
	if hasMore {
		reply.NextCursor = strconv.Itoa(end)
	}
	return reply, nil
}

func normalizeRange(input string) string {
	switch strings.TrimSpace(strings.ToLower(input)) {
	case "24h", "all-time":
		return strings.TrimSpace(strings.ToLower(input))
	default:
		return "live"
	}
}

func indexSecrets(items []store.Item) (map[string]Secret, map[string]Secret, []Secret) {
	byName := make(map[string]Secret, len(items))
	byID := make(map[string]Secret, len(items))
	secrets := make([]Secret, 0, len(items))
	for _, item := range items {
		secret := Secret{ID: item.ID, Path: item.Name, Version: item.UpdatedAt.UTC().Format(time.RFC3339Nano)}
		byName[item.Name] = secret
		byID[item.ID] = secret
		secrets = append(secrets, secret)
	}
	sort.SliceStable(secrets, func(i, j int) bool {
		if secrets[i].Path == secrets[j].Path {
			return secrets[i].ID < secrets[j].ID
		}
		return secrets[i].Path < secrets[j].Path
	})
	return byName, byID, secrets
}

func collectConsumers(input Input, filter string) []Consumer {
	seen := make(map[string]Consumer)
	for _, consumer := range input.AppConsumers {
		id := strings.TrimSpace(consumer.Name)
		if id != "" {
			seen[id] = Consumer{ID: id, Name: id, Kind: string(store.ConsumerKindApp)}
		}
	}
	for _, consumer := range input.AgentConsumers {
		id := strings.TrimSpace(consumer.Name)
		if id != "" {
			seen[id] = Consumer{ID: id, Name: id, Kind: string(store.ConsumerKindAgent)}
		}
	}
	for _, session := range input.Sessions {
		id := strings.TrimSpace(session.ConsumerID)
		if id != "" {
			if _, ok := seen[id]; !ok {
				seen[id] = Consumer{ID: id, Name: id, Kind: "session"}
			}
		}
	}
	for _, lease := range input.Leases {
		id := strings.TrimSpace(lease.ConsumerID)
		if id != "" {
			if _, ok := seen[id]; !ok {
				seen[id] = Consumer{ID: id, Name: id, Kind: "session"}
			}
		}
	}
	out := make([]Consumer, 0, len(seen))
	for _, consumer := range seen {
		if filter != "" && consumer.ID != filter && consumer.Name != filter {
			continue
		}
		out = append(out, consumer)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ID == out[j].ID {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func indexSessions(sessions []Session) map[string]string {
	out := make(map[string]string, len(sessions))
	for _, session := range sessions {
		if strings.TrimSpace(session.Token) == "" || strings.TrimSpace(session.ConsumerID) == "" {
			continue
		}
		out[session.Token] = session.ConsumerID
	}
	return out
}

func indexActiveLeases(input []leases.Lease, byName map[string]Secret, byID map[string]Secret) (map[string]int, map[string]time.Time) {
	counts := make(map[string]int)
	lastUsed := make(map[string]time.Time)
	for _, lease := range input {
		if strings.TrimSpace(lease.Status) != "active" {
			continue
		}
		secretID := resolveSecretID(lease.SecretID, byName, byID)
		if _, ok := byID[secretID]; !ok {
			continue
		}
		key := strings.TrimSpace(lease.ConsumerID) + "\x00" + secretID
		if key == "\x00" {
			continue
		}
		counts[key]++
		if lease.LastUsedAt.After(lastUsed[key]) {
			lastUsed[key] = lease.LastUsedAt
		}
	}
	return counts, lastUsed
}

func resolveSecretID(ref string, byName map[string]Secret, byID map[string]Secret) string {
	ref = strings.TrimSpace(ref)
	if secret, ok := byID[ref]; ok {
		return secret.ID
	}
	if secret, ok := byName[ref]; ok {
		return secret.ID
	}
	return ref
}

func matchesGrant(grant Grant, opts Options, secrets map[string]Secret) bool {
	if opts.Consumer != "" && grant.ConsumerID != opts.Consumer {
		return false
	}
	if opts.Secret != "" {
		secret, ok := secrets[grant.SecretID]
		if !ok || (secret.ID != opts.Secret && secret.Path != opts.Secret) {
			return false
		}
	}
	if opts.Scope != "" && grant.Scope != opts.Scope {
		return false
	}
	if opts.Source != "" && grant.Source != opts.Source {
		return false
	}
	if opts.HasActiveLease != nil && (grant.LeaseCount > 0) != *opts.HasActiveLease {
		return false
	}
	return true
}

func filterSecrets(secrets []Secret, filter string) []Secret {
	if strings.TrimSpace(filter) == "" {
		return secrets
	}
	out := make([]Secret, 0, 1)
	for _, secret := range secrets {
		if secret.ID == filter || secret.Path == filter {
			out = append(out, secret)
		}
	}
	return out
}

func grantSortKey(grant Grant) string {
	return grant.ConsumerID + "\x00" + grant.SecretID + "\x00" + grant.Source + "\x00" + grant.Scope
}

func cursorStart(grants []Grant, cursor string) (int, error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return 0, nil
	}
	offset, err := strconv.Atoi(cursor)
	if err != nil || offset < 0 {
		return 0, fmt.Errorf("invalid cursor %q", cursor)
	}
	if offset > len(grants) {
		return len(grants), nil
	}
	return offset, nil
}

func projectCells(input Input, matrixRange string, consumers []Consumer, secrets []Secret, grants map[string]Grant) []Cell {
	now := input.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	secretByID := make(map[string]Secret, len(secrets))
	for _, secret := range secrets {
		secretByID[secret.ID] = secret
	}
	grantByCell := make(map[string][]Grant)
	for _, grant := range grants {
		key := grant.ConsumerID + "\x00" + grant.SecretID
		grantByCell[key] = append(grantByCell[key], grant)
	}
	pendingByCell := pendingApprovalsByCell(input.Approvals, secretByID)
	auditByCell := latestAuditByCell(input.AuditEvents, secretByID, now, matrixRange)
	cells := make([]Cell, 0, len(consumers)*len(secrets))
	for _, consumer := range consumers {
		for _, secret := range secrets {
			key := consumer.ID + "\x00" + secret.ID
			cell := Cell{ConsumerID: consumer.ID, SecretID: secret.ID, State: "never", Glyph: "-", Label: "never"}
			if approval, ok := pendingByCell[key]; ok {
				cell = Cell{
					ConsumerID: consumer.ID,
					SecretID:   secret.ID,
					State:      "pending",
					Glyph:      "dot",
					Label:      "pending",
					SubText:    durationText(now.Sub(approval.RequestedAt)),
					Scope:      approval.RequestedScope,
					Source:     "approval",
					ApprovalID: approval.ID,
				}
			} else if live := highestLiveGrant(grantByCell[key]); live != nil {
				state, glyph, label := "active", "check", live.Scope
				if strings.Contains(live.Scope, "session") {
					state, glyph, label = "session", "clock", "session"
				}
				if expiringLease(input.Leases, consumer.ID, secret.ID, now) {
					state, glyph, label = "expiring", "warn", "expiring"
				}
				cell = Cell{
					ConsumerID: consumer.ID,
					SecretID:   secret.ID,
					State:      state,
					Glyph:      glyph,
					Label:      label,
					SubText:    live.LastUsedAt,
					Scope:      live.Scope,
					Source:     live.Source,
					LastUsedAt: live.LastUsedAt,
					LeaseCount: live.LeaseCount,
				}
			} else if auditCell, ok := auditByCell[key]; ok {
				cell = auditCell
			}
			cells = append(cells, cell)
		}
	}
	return cells
}

func pendingApprovalsByCell(input []approvals.Approval, secrets map[string]Secret) map[string]approvals.Approval {
	out := make(map[string]approvals.Approval)
	for _, approval := range input {
		if approval.Status != "pending" {
			continue
		}
		secretID := resolveSecretID(approval.SecretID, nil, secrets)
		if _, ok := secrets[secretID]; !ok {
			continue
		}
		key := strings.TrimSpace(approval.RequesterConsumerID) + "\x00" + secretID
		if key == "\x00" {
			continue
		}
		if existing, ok := out[key]; !ok || approval.RequestedAt.Before(existing.RequestedAt) {
			out[key] = approval
		}
	}
	return out
}

func highestLiveGrant(grants []Grant) *Grant {
	var best *Grant
	for i := range grants {
		if grants[i].LeaseCount <= 0 {
			continue
		}
		if best == nil || grants[i].LastUsedAt > best.LastUsedAt {
			best = &grants[i]
		}
	}
	return best
}

func expiringLease(input []leases.Lease, consumerID, secretID string, now time.Time) bool {
	for _, lease := range input {
		if lease.Status != "active" || lease.ConsumerID != consumerID || strings.TrimSpace(lease.SecretID) != secretID {
			continue
		}
		remaining := lease.ExpiresAt.Sub(now)
		if remaining > 0 && remaining < time.Minute {
			return true
		}
	}
	return false
}

func latestAuditByCell(events []audit.Event, secrets map[string]Secret, now time.Time, matrixRange string) map[string]Cell {
	out := make(map[string]Cell)
	for _, event := range events {
		if matrixRange == "live" {
			continue
		}
		if matrixRange == "24h" && event.Timestamp.Before(now.Add(-24*time.Hour)) {
			continue
		}
		consumerID := auditString(event.Details, "consumer_id", "consumer_name", "requester_consumer_id", "actor")
		secretRef := auditString(event.Details, "secret_id", "item_id", "item_name", "secret")
		secretID := resolveSecretID(secretRef, nil, secrets)
		if consumerID == "" || secretID == "" {
			continue
		}
		if _, ok := secrets[secretID]; !ok {
			continue
		}
		key := consumerID + "\x00" + secretID
		if existing, ok := out[key]; ok && existing.AuditSeq > event.Sequence {
			continue
		}
		state, glyph, label := "past", "circle", "past"
		outcome := strings.ToLower(event.Type + " " + auditString(event.Details, "outcome", "status", "action"))
		if event.Type == audit.EventDeny || strings.Contains(outcome, "deny") || strings.Contains(outcome, "denied") {
			state, glyph, label = "denied", "x", "denied"
		}
		out[key] = Cell{
			ConsumerID: consumerID,
			SecretID:   secretID,
			State:      state,
			Glyph:      glyph,
			Label:      label,
			SubText:    event.Timestamp.UTC().Format(time.RFC3339Nano),
			Source:     "audit",
			LastUsedAt: event.Timestamp.UTC().Format(time.RFC3339Nano),
			AuditSeq:   event.Sequence,
		}
	}
	return out
}

func auditString(details map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := details[key]; ok {
			if out := strings.TrimSpace(fmt.Sprint(value)); out != "" {
				return out
			}
		}
	}
	return ""
}

func durationText(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return strconv.Itoa(int(d.Seconds())) + "s"
	}
	if d < time.Hour {
		return strconv.Itoa(int(d.Minutes())) + "m"
	}
	return strconv.Itoa(int(d.Hours())) + "h"
}
