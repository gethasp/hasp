package runtime

import "time"

const (
	DefaultSessionTTL       = 30 * time.Minute
	DefaultVaultIdleTimeout = 10 * time.Minute
)

type PingRequest struct{}

type PingResponse struct {
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	ServerTime time.Time `json:"server_time"`
}

type StatusRequest struct{}

type StatusResponse struct {
	SocketPath      string        `json:"socket_path"`
	PID             int           `json:"pid"`
	StartedAt       time.Time     `json:"started_at"`
	ActiveSessions  int           `json:"active_sessions"`
	Sessions        []SessionView `json:"sessions"`
	AuditDegraded   bool          `json:"audit_degraded"`
	AuditDegradedAt *time.Time    `json:"audit_degraded_at,omitempty"`
}

type OpenSessionRequest struct {
	HostLabel    string `json:"host_label"`
	ProjectRoot  string `json:"project_root"`
	TTLSeconds   int    `json:"ttl_seconds"`
	AgentSafe    bool   `json:"agent_safe,omitempty"`
	ConsumerName string `json:"consumer_name,omitempty"`
}

type OpenSessionResponse struct {
	SessionID    string    `json:"session_id"`
	SessionToken string    `json:"session_token"`
	LocalUser    string    `json:"local_user"`
	HostLabel    string    `json:"host_label"`
	ProjectRoot  string    `json:"project_root"`
	AgentSafe    bool      `json:"agent_safe,omitempty"`
	ConsumerName string    `json:"consumer_name,omitempty"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type RevokeSessionRequest struct {
	SessionToken string `json:"session_token"`
}

type RevokeSessionResponse struct {
	Revoked      bool `json:"revoked"`
	RevokedCount int  `json:"revoked_count,omitempty"`
}

type RevokeAllSessionsRequest struct{}

type RevokeAllSessionsResponse struct {
	RevokedCount int `json:"revoked_count"`
}

type LockVaultRequest struct{}

type LockVaultResponse struct {
	RevokedCount int  `json:"revoked_count"`
	Locked       bool `json:"locked"`
}

type ResolveSessionRequest struct {
	SessionToken string `json:"session_token"`
}

type ResolveSessionResponse struct {
	Session SessionView `json:"session"`
}

type RegisterProcessRequest struct {
	SessionToken string `json:"session_token"`
	PID          int    `json:"pid"`
}

type RegisterProcessResponse struct {
	Registered bool `json:"registered"`
}

type ResolveProcessRequest struct {
	PID int `json:"pid"`
}

type ResolveProcessResponse struct {
	Found        bool        `json:"found"`
	SessionToken string      `json:"session_token,omitempty"`
	Session      SessionView `json:"session,omitempty"`
}
