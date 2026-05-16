package store

import "time"

type GrantScope string

const (
	GrantOnce    GrantScope = "once"
	GrantSession GrantScope = "session"
	GrantWindow  GrantScope = "window"
)

const (
	DefaultPlaintextGrantTTL = 60 * time.Second
	MaxPlaintextGrantTTL     = 2 * time.Minute
	DefaultMutationGrantTTL  = 60 * time.Second
	MaxMutationGrantTTL      = 2 * time.Minute
)

type Operation string

const (
	OperationList     Operation = "list"
	OperationRun      Operation = "run"
	OperationInject   Operation = "inject"
	OperationWriteEnv Operation = "write-env"
	OperationCapture  Operation = "capture"
)

type PlaintextAction string

const (
	PlaintextReveal PlaintextAction = "reveal"
	PlaintextCopy   PlaintextAction = "copy"
)

type SecretMutationAction string

const (
	SecretMutationDelete SecretMutationAction = "delete"
	SecretMutationExpose SecretMutationAction = "expose"
	SecretMutationHide   SecretMutationAction = "hide"
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

type PlaintextGrant struct {
	ID           string          `json:"id"`
	SessionToken string          `json:"session_token"`
	ItemName     string          `json:"item_name"`
	Action       PlaintextAction `json:"action"`
	GrantedBy    string          `json:"granted_by"`
	Scope        GrantScope      `json:"scope"`
	ExpiresAt    *time.Time      `json:"expires_at,omitempty"`
	RevokedAt    *time.Time      `json:"revoked_at,omitempty"`
	UsedAt       *time.Time      `json:"used_at,omitempty"`
}

type MutationGrant struct {
	ID           string               `json:"id"`
	BindingID    string               `json:"binding_id"`
	ItemName     string               `json:"item_name"`
	SessionToken string               `json:"session_token"`
	Action       SecretMutationAction `json:"action"`
	GrantedBy    string               `json:"granted_by"`
	Scope        GrantScope           `json:"scope"`
	ExpiresAt    *time.Time           `json:"expires_at,omitempty"`
	RevokedAt    *time.Time           `json:"revoked_at,omitempty"`
	UsedAt       *time.Time           `json:"used_at,omitempty"`
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

type AccessRequirement string

const (
	AccessRequirementNone                  AccessRequirement = ""
	AccessRequirementProjectLease          AccessRequirement = "project_lease"
	AccessRequirementProjectAndConvenience AccessRequirement = "project_and_convenience"
	AccessRequirementConvenience           AccessRequirement = "convenience"
	AccessRequirementSecretGrant           AccessRequirement = "secret_grant"
	AccessRequirementWriteGrant            AccessRequirement = "write_grant"
	AccessRequirementUnsupported           AccessRequirement = "unsupported"
)

type AccessDecision struct {
	Allowed        bool              `json:"allowed"`
	RequiresPrompt bool              `json:"requires_prompt"`
	Reason         string            `json:"reason"`
	Requirement    AccessRequirement `json:"requirement,omitempty"`
}

func (d AccessDecision) RequiredAction() AccessRequirement {
	if d.Requirement != "" {
		return d.Requirement
	}
	switch d.Reason {
	case "project_lease_required":
		return AccessRequirementProjectLease
	case "project_and_convenience_approval_required":
		return AccessRequirementProjectAndConvenience
	case "convenience_approval_required":
		return AccessRequirementConvenience
	case "secret_session_grant_required", "access_secret_prompt_required":
		return AccessRequirementSecretGrant
	case "write_grant_required":
		return AccessRequirementWriteGrant
	case "unsupported_operation", "unknown_policy":
		return AccessRequirementUnsupported
	default:
		return AccessRequirementNone
	}
}
