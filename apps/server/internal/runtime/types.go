package runtime

import (
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/accessmatrix"
	"github.com/gethasp/hasp/apps/server/internal/app/dashboard"
	"github.com/gethasp/hasp/apps/server/internal/approvals"
	"github.com/gethasp/hasp/apps/server/internal/integrations"
	"github.com/gethasp/hasp/apps/server/internal/leases"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

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
	// ProcessIdentityDegraded is true when process binding fell back to
	// ancestry-only checks because the platform probe could not produce a stable
	// per-process identity token.
	ProcessIdentityDegraded       bool                   `json:"process_identity_degraded"`
	ProcessIdentityDegradedReason string                 `json:"process_identity_degraded_reason,omitempty"`
	LeasesCount                   int                    `json:"leases_count"`
	ApprovalsPending              int                    `json:"approvals_pending"`
	Expiring30m                   int                    `json:"expiring_30m"`
	AuditHealth                   string                 `json:"audit_health"`
	Vault                         dashboard.Vault        `json:"vault"`
	Leases                        dashboard.Leases       `json:"leases"`
	Approvals                     dashboard.Approvals    `json:"approvals"`
	Audit                         dashboard.Audit        `json:"audit"`
	Integrations                  dashboard.Integrations `json:"integrations"`
	Daemon                        dashboard.Daemon       `json:"daemon"`
}

type VaultStatusResponse struct {
	Schema       int     `json:"_schema"`
	State        string  `json:"state"`
	Locked       bool    `json:"locked"`
	RemainingTTL float64 `json:"remaining_ttl,omitempty"`
}

type InitVaultRequest struct {
	MasterPassword string `json:"master_password"`
}

type InitVaultResponse struct {
	Schema       int     `json:"_schema"`
	Initialized  bool    `json:"initialized"`
	Unlocked     bool    `json:"unlocked"`
	RemainingTTL float64 `json:"remaining_ttl,omitempty"`
}

type UnlockVaultRequest struct {
	Method string `json:"method,omitempty"`
}

type UnlockVaultResponse struct {
	Unlocked     bool    `json:"unlocked"`
	RemainingTTL float64 `json:"remaining_ttl"`
}

type OpenSessionRequest struct {
	HostLabel   string `json:"host_label"`
	ProjectRoot string `json:"project_root"`
	TTLSeconds  int    `json:"ttl_seconds"`
	// TTLMillis lets callers request sub-second TTL for tests that exercise
	// the expiry-rejection codepath without long sleeps. When non-zero it
	// takes precedence over TTLSeconds. Callers that need >1s TTL keep
	// using TTLSeconds. hasp-4xf9.
	TTLMillis    int    `json:"ttl_millis,omitempty"`
	AgentSafe    bool   `json:"agent_safe,omitempty"`
	ConsumerName string `json:"consumer_name,omitempty"`
	Internal     bool   `json:"internal,omitempty"`
	// AuditHMACKey lets an already-unlocked caller hand the daemon the
	// vault-derived audit key for daemon-owned session lifecycle events. It is
	// process-local RPC data over the protected daemon socket, never persisted.
	AuditHMACKey []byte `json:"audit_hmac_key,omitempty"`
}

type OpenSessionResponse struct {
	SessionID    string    `json:"session_id"`
	SessionToken string    `json:"session_token"`
	LocalUser    string    `json:"local_user"`
	HostLabel    string    `json:"host_label"`
	ProjectRoot  string    `json:"project_root"`
	AgentSafe    bool      `json:"agent_safe,omitempty"`
	ConsumerName string    `json:"consumer_name,omitempty"`
	Internal     bool      `json:"internal,omitempty"`
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

type ListLeasesRequest struct {
	ConsumerID        string `json:"consumer_id,omitempty"`
	Status            string `json:"status,omitempty"`
	ExpiringInSeconds int    `json:"expiring_in_s,omitempty"`
	Cursor            string `json:"cursor,omitempty"`
	Limit             int    `json:"limit,omitempty"`
}

type Lease = leases.Lease
type ListLeasesResponse = leases.Response

type AccessMatrixRequest struct {
	Range          string `json:"range,omitempty"`
	Consumer       string `json:"consumer,omitempty"`
	Secret         string `json:"secret,omitempty"`
	Scope          string `json:"scope,omitempty"`
	Source         string `json:"source,omitempty"`
	HasActiveLease *bool  `json:"has_active_lease,omitempty"`
	Cursor         string `json:"cursor,omitempty"`
	Limit          int    `json:"limit,omitempty"`
}

type AccessMatrixConsumer = accessmatrix.Consumer
type AccessMatrixSecret = accessmatrix.Secret
type AccessMatrixGrant = accessmatrix.Grant
type AccessMatrixResponse = accessmatrix.Response

type PolicyDocument = store.PolicyDocument
type PolicyRule = store.PolicyRule
type PolicyMatch = store.PolicyMatch

type PolicyGetRequest struct{}

type PolicySetRequest struct {
	Policy          PolicyDocument `json:"policy"`
	IfMatch         string         `json:"if_match,omitempty"`
	Force           bool           `json:"force,omitempty"`
	UpdatedBy       string         `json:"updated_by,omitempty"`
	ValidateOnly    bool           `json:"validate_only,omitempty"`
	ReturnValidated bool           `json:"return_validated,omitempty"`
}

type PolicyResponse struct {
	Schema int `json:"_schema"`
	PolicyDocument
}

type ConfigDocument = store.ConfigDocument
type ConfigValue = store.ConfigValue

type ConfigGetRequest struct{}

type ConfigSetRequest struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
	Actor string `json:"actor,omitempty"`
}

type ConfigResponse struct {
	Schema int            `json:"_schema"`
	Config ConfigDocument `json:"config"`
}

type ConfigValueResponse struct {
	Schema int    `json:"_schema"`
	Key    string `json:"key"`
	Value  any    `json:"value"`
}

type RotateMasterPasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type RotateMasterPasswordResponse struct {
	Schema       int  `json:"_schema"`
	Rotated      bool `json:"rotated"`
	RevokedCount int  `json:"revoked_count"`
}

type HTTPKeyFingerprintResponse struct {
	Schema      int    `json:"_schema"`
	Fingerprint string `json:"fingerprint"`
}

type BackupRequest struct {
	DestinationPath string `json:"destination_path"`
	Passphrase      string `json:"passphrase"`
}

type BackupPassphraseRequest struct {
	Passphrase string `json:"passphrase"`
}

type BackupPassphraseStatusResponse struct {
	Schema    int    `json:"_schema"`
	Enrolled  bool   `json:"enrolled"`
	Available bool   `json:"available"`
	Source    string `json:"source,omitempty"`
}

type BackupResponse struct {
	Schema     int                         `json:"_schema"`
	Path       string                      `json:"path"`
	Checkpoint store.AuditCheckpoint       `json:"checkpoint"`
	Pruned     bool                        `json:"pruned"`
	Signature  store.BackupSignatureStatus `json:"signature"`
}

type Integration = integrations.Integration
type IntegrationProfile = integrations.Profile
type IntegrationDoctorCheck = integrations.DoctorCheck
type IntegrationListResponse = integrations.ListResponse
type IntegrationProfilesResponse = integrations.ProfilesResponse
type IntegrationProfileMutationRequest = integrations.ProfileMutationRequest
type IntegrationProfileMutationResponse = integrations.ProfileMutationResponse
type IntegrationDoctorRequest = integrations.DoctorRequest
type IntegrationDoctorResponse = integrations.DoctorResponse

type IntegrationGetRequest struct{}

type IntegrationProfilesRequest struct {
	TargetID string `json:"target_id"`
}

type IntegrationDoctorRPCRequest struct {
	TargetID  string `json:"target_id"`
	ProfileID string `json:"profile_id,omitempty"`
}

type IntegrationProfileMutationRPCRequest struct {
	TargetID  string                            `json:"target_id,omitempty"`
	ProfileID string                            `json:"profile_id,omitempty"`
	IfMatch   string                            `json:"if_match,omitempty"`
	Body      IntegrationProfileMutationRequest `json:"body"`
}

type SecretListItem struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Path         string   `json:"path"`
	Ref          string   `json:"ref"`
	Kind         string   `json:"kind,omitempty"`
	Policy       string   `json:"policy,omitempty"`
	Version      string   `json:"version"`
	LastModified string   `json:"last_modified"`
	LastRevealed string   `json:"last_revealed,omitempty"`
	Tags         []string `json:"tags,omitempty"`
}

type SecretsListResponse struct {
	Schema  int              `json:"_schema"`
	Secrets []SecretListItem `json:"secrets"`
}

type RevokeLeaseRequest struct {
	LeaseID        string   `json:"lease_id,omitempty"`
	LeaseIDs       []string `json:"lease_ids,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	AllForConsumer string   `json:"all_for_consumer,omitempty"`
}

type RevokeLeaseResponse struct {
	Revoked      bool `json:"revoked"`
	RevokedCount int  `json:"revoked_count"`
}

type ListApprovalsRequest struct {
	Status     string `json:"status,omitempty"`
	ConsumerID string `json:"consumer_id,omitempty"`
}

type Approval = approvals.Approval
type ApprovalDecision = approvals.Decision
type ListApprovalsResponse = approvals.Response

type ApprovalDetailResponse struct {
	Approval          Approval     `json:"approval"`
	RequesterVerifier string       `json:"requester_verifier"`
	ConsumerHistory   []Approval   `json:"consumer_history"`
	AuditTrail        []AuditEntry `json:"audit_trail"`
	GeneratedAt       time.Time    `json:"generated_at"`
}

type DecideApprovalRequest struct {
	ApprovalID     string `json:"approval_id,omitempty"`
	Decision       string `json:"decision"`
	GrantedTTLS    int    `json:"granted_ttl_s,omitempty"`
	Scope          string `json:"scope,omitempty"`
	Reason         string `json:"reason,omitempty"`
	Actor          string `json:"actor,omitempty"`
	AuthMethod     string `json:"auth_method,omitempty"`
	HoldDurationMS int    `json:"hold_duration_ms,omitempty"`
}

type DecideApprovalResponse struct {
	Approval Approval `json:"approval"`
	LeaseID  string   `json:"lease_id,omitempty"`
	Changed  bool     `json:"changed"`
}

type AuditEntry struct {
	ID        string    `json:"id"`
	Sequence  int64     `json:"sequence"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Action    string    `json:"action"`
	Actor     string    `json:"actor,omitempty"`
	Target    string    `json:"target,omitempty"`
	Details   string    `json:"details,omitempty"`
	Hash      string    `json:"hash,omitempty"`
}

type AuditListResponse struct {
	Schema  int          `json:"_schema"`
	Entries []AuditEntry `json:"entries"`
}

type AuditVerifyResponse struct {
	Schema            int        `json:"_schema"`
	ChainOK           bool       `json:"chain_ok"`
	LastVerifiedAt    *time.Time `json:"last_verified_at,omitempty"`
	TotalEntries      int        `json:"total_entries"`
	FirstCorruptionAt *int64     `json:"first_corruption_at,omitempty"`
	Error             string     `json:"error,omitempty"`
	OK                bool       `json:"ok"`
	CheckedCount      int        `json:"checked_count"`
}

type LockVaultRequest struct {
	Cause string `json:"cause,omitempty"`
}

type LockVaultResponse struct {
	RevokedCount int  `json:"revoked_count"`
	Locked       bool `json:"locked"`
}

type RestartDaemonRequest struct {
	Reason string `json:"reason,omitempty"`
}

type RestartDaemonResponse struct {
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason"`
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
