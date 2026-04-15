package store

import "time"

type GrantScope string

const (
	GrantOnce    GrantScope = "once"
	GrantSession GrantScope = "session"
	GrantWindow  GrantScope = "window"
)

type Operation string

const (
	OperationList     Operation = "list"
	OperationRun      Operation = "run"
	OperationInject   Operation = "inject"
	OperationWriteEnv Operation = "write-env"
	OperationCapture  Operation = "capture"
)

type ProjectLease struct {
	ID           string     `json:"id"`
	BindingID    string     `json:"binding_id"`
	SessionToken string     `json:"session_token"`
	Scope        GrantScope `json:"scope"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	UsedAt       *time.Time `json:"used_at,omitempty"`
}

type SecretGrant struct {
	ID              string     `json:"id"`
	BindingID       string     `json:"binding_id"`
	ItemName        string     `json:"item_name"`
	SessionToken    string     `json:"session_token"`
	Scope           GrantScope `json:"scope"`
	RelaxedByWindow bool       `json:"relaxed_by_window"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	UsedAt          *time.Time `json:"used_at,omitempty"`
}

type ConvenienceGrant struct {
	ID                  string     `json:"id"`
	ProjectBindingID    string     `json:"project_binding_id"`
	LeaseID             string     `json:"lease_id"`
	DestinationPathHash string     `json:"destination_path_hash"`
	ResolvedSetHash     string     `json:"resolved_set_hash"`
	GrantedBy           string     `json:"granted_by"`
	Scope               GrantScope `json:"scope"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
	UsedAt              *time.Time `json:"used_at,omitempty"`
}

type AccessRequest struct {
	Operation       Operation
	BindingID       string
	SessionToken    string
	ItemName        string
	Policy          SecretPolicy
	DestinationPath string
	Aliases         []string
	CreatingNew     bool
}

type AccessDecision struct {
	Allowed        bool   `json:"allowed"`
	RequiresPrompt bool   `json:"requires_prompt"`
	Reason         string `json:"reason"`
}
