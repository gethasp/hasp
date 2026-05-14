package leases

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

const DefaultLimit = 100

type Lease struct {
	ID         string    `json:"id"`
	SecretID   string    `json:"secret_id"`
	ConsumerID string    `json:"consumer_id"`
	GrantedAt  time.Time `json:"granted_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	Scope      string    `json:"scope"`
	Status     string    `json:"status"`
}

type ListOptions struct {
	ConsumerID string
	Status     string
	ExpiringIn time.Duration
	Cursor     string
	Limit      int
	Now        time.Time
}

type Response struct {
	Leases     []Lease `json:"leases"`
	Total      int     `json:"total"`
	HasMore    bool    `json:"has_more"`
	NextCursor string  `json:"next_cursor,omitempty"`
}

func List(input []Lease, opts ListOptions) Response {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > DefaultLimit {
		limit = DefaultLimit
	}
	consumer := strings.TrimSpace(opts.ConsumerID)
	status := strings.TrimSpace(opts.Status)
	filtered := make([]Lease, 0, len(input))
	for _, lease := range input {
		if consumer != "" && lease.ConsumerID != consumer {
			continue
		}
		if status != "" && lease.Status != status {
			continue
		}
		if opts.ExpiringIn > 0 {
			if lease.Status != "active" {
				continue
			}
			if lease.ExpiresAt.Before(now) || lease.ExpiresAt.After(now.Add(opts.ExpiringIn)) {
				continue
			}
		}
		filtered = append(filtered, lease)
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].GrantedAt.Equal(filtered[j].GrantedAt) {
			return filtered[i].ID < filtered[j].ID
		}
		return filtered[i].GrantedAt.After(filtered[j].GrantedAt)
	})
	start := cursorStart(filtered, opts.Cursor)
	total := len(filtered)
	end := start + limit
	hasMore := end < total
	if end > total {
		end = total
	}
	reply := Response{Leases: filtered[start:end], Total: total, HasMore: hasMore}
	if hasMore {
		reply.NextCursor = stableCursor(filtered[end-1])
	}
	return reply
}

func cursorStart(leases []Lease, cursor string) int {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return 0
	}
	if offset, err := strconv.Atoi(cursor); err == nil {
		if offset < 0 {
			return 0
		}
		if offset > len(leases) {
			return len(leases)
		}
		return offset
	}
	rawTime, id, ok := strings.Cut(cursor, "|")
	if !ok || id == "" {
		return 0
	}
	nanos, err := strconv.ParseInt(rawTime, 10, 64)
	if err != nil {
		return 0
	}
	for index, lease := range leases {
		if lease.ID == id && lease.GrantedAt.UnixNano() == nanos {
			return index + 1
		}
	}
	return 0
}

func stableCursor(lease Lease) string {
	return strconv.FormatInt(lease.GrantedAt.UnixNano(), 10) + "|" + lease.ID
}
