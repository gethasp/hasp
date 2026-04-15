package runtime

import "time"

const DefaultSessionTTL = 30 * time.Minute

type PingRequest struct{}

type PingResponse struct {
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	ServerTime time.Time `json:"server_time"`
}

type StatusRequest struct{}

type StatusResponse struct {
	SocketPath     string        `json:"socket_path"`
	PID            int           `json:"pid"`
	StartedAt      time.Time     `json:"started_at"`
	ActiveSessions int           `json:"active_sessions"`
	Sessions       []SessionView `json:"sessions"`
}

type OpenSessionRequest struct {
	HostLabel   string `json:"host_label"`
	ProjectRoot string `json:"project_root"`
	TTLSeconds  int    `json:"ttl_seconds"`
}

type OpenSessionResponse struct {
	SessionID    string    `json:"session_id"`
	SessionToken string    `json:"session_token"`
	LocalUser    string    `json:"local_user"`
	HostLabel    string    `json:"host_label"`
	ProjectRoot  string    `json:"project_root"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type RevokeSessionRequest struct {
	SessionToken string `json:"session_token"`
}

type RevokeSessionResponse struct {
	Revoked bool `json:"revoked"`
}

type ResolveSessionRequest struct {
	SessionToken string `json:"session_token"`
}

type ResolveSessionResponse struct {
	Session SessionView `json:"session"`
}
