package store

import (
	"errors"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
)

const (
	formatVersion                = 1
	productionPasswordIterations = 600_000
	testPasswordIterations       = 100_000
	keyLength                    = 32
	keyringService               = "com.gethasp.v1"
)

var (
	ErrVaultExists         = errors.New("vault already exists")
	ErrVaultNotInitialized = errors.New("vault not initialized")
	ErrInvalidPassword     = errors.New("invalid master password")
	ErrItemNotFound        = errors.New("item not found")
	ErrKeyringUnavailable  = errors.New("keyring convenience unlock unavailable")
	// passwordIterations is retained only for PBKDF2 metadata/backward-
	// compatibility reporting. New vaults use argon2id parameters below.
	// Do not read HASP_KDF_ITERATIONS at package init: even `hasp --help`
	// must survive a bad shell environment.
	passwordIterations = defaultPasswordIterations
)

// FormatVersion returns the on-disk envelope format version every freshly
// initialised vault stamps into its header. Operators read it via
// `hasp version --json` to confirm a binary will write a vault their other
// tools can decrypt.
func FormatVersion() int { return formatVersion }

// DefaultKDFName returns the canonical name of the KDF used to wrap the
// vault key on init. Surfaced through `hasp version --json` so an operator
// auditing a binary can correlate it against the spec recorded in their
// vault envelope. Switched from "pbkdf2-sha256" to "argon2id" in 0.1.x —
// pbkdf2-sha256 still opens existing vaults via the dispatch in deriveFromSpec.
func DefaultKDFName() string { return kdfNameArgon2id }

// DefaultKDFIterations returns the legacy PBKDF2 iteration count retained for
// backwards-compatible diagnostics. With argon2id as the new default it no
// longer drives new vaults and is reported alongside
// DefaultKDFTime/Memory/Parallelism.
func DefaultKDFIterations() int { return passwordIterations }

// DefaultKDFTime returns the argon2id `t` parameter (number of passes) the
// current binary uses when initialising a new vault.
func DefaultKDFTime() uint32 { return passwordArgon2Time }

// DefaultKDFMemoryKiB returns the argon2id `m` parameter in KiB the current
// binary uses when initialising a new vault.
func DefaultKDFMemoryKiB() uint32 { return passwordArgon2MemoryKiB }

// DefaultKDFParallelism returns the argon2id `p` parameter the current binary
// uses when initialising a new vault.
func DefaultKDFParallelism() uint8 { return passwordArgon2Parallelism }

type ItemKind string

const (
	ItemKindKV   ItemKind = "kv"
	ItemKindFile ItemKind = "file"
)

type SecretPolicy string

const (
	PolicyAuto    SecretPolicy = "auto"
	PolicySession SecretPolicy = "session"
	PolicyAccess  SecretPolicy = "access"
)

type ItemMetadata struct {
	Notes           string       `json:"notes,omitempty"`
	Tags            []string     `json:"tags,omitempty"`
	ProjectBindings []string     `json:"project_bindings,omitempty"`
	HumanLabel      string       `json:"human_label,omitempty"`
	Policy          SecretPolicy `json:"policy,omitempty"`
}

type Item struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Kind      ItemKind     `json:"kind"`
	Value     []byte       `json:"value"`
	Metadata  ItemMetadata `json:"metadata"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
	DeletedAt *time.Time   `json:"deleted_at,omitempty"`
}

type ConsumerKind string

const (
	ConsumerKindApp   ConsumerKind = "app"
	ConsumerKindAgent ConsumerKind = "agent"
)

type AppDeliveryMode string

const (
	AppDeliveryEnv        AppDeliveryMode = "env"
	AppDeliveryTempFile   AppDeliveryMode = "temp_file"
	AppDeliveryTempDotenv AppDeliveryMode = "temp_dotenv"
)

type AppBinding struct {
	SecretName string          `json:"secret_name"`
	Delivery   AppDeliveryMode `json:"delivery"`
	Target     string          `json:"target"`
}

type AppConsumer struct {
	Name         string       `json:"name"`
	ProjectRoot  string       `json:"project_root"`
	Command      []string     `json:"command"`
	Bindings     []AppBinding `json:"bindings"`
	DotenvEnv    string       `json:"dotenv_env,omitempty"`
	LauncherPath string       `json:"launcher_path,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

type AgentConsumer struct {
	Name        string    `json:"name"`
	AgentID     string    `json:"agent_id"`
	ProjectRoot string    `json:"project_root,omitempty"`
	ConfigPath  string    `json:"config_path"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Store struct {
	paths   paths.Paths
	keyring Keyring
	audit   *audit.Log
	now     func() time.Time
}

type Handle struct {
	store    *Store
	state    persistedState
	vaultKey []byte
}

type persistedState struct {
	Items             map[string]Item             `json:"items"`
	Bindings          map[string]Binding          `json:"bindings"`
	ProjectLeases     map[string]ProjectLease     `json:"project_leases"`
	SecretGrants      map[string]SecretGrant      `json:"secret_grants"`
	ConvenienceGrants map[string]ConvenienceGrant `json:"convenience_grants"`
	PlaintextGrants   map[string]PlaintextGrant   `json:"plaintext_grants"`
	AppConsumers      map[string]AppConsumer      `json:"app_consumers"`
	AgentConsumers    map[string]AgentConsumer    `json:"agent_consumers"`
	ManifestReviews   map[string]ManifestReview   `json:"manifest_reviews,omitempty"`
}

type fileEnvelope struct {
	Header envelopeHeader `json:"header"`
	Data   sealedBlob     `json:"data"`
}

type envelopeHeader struct {
	Version         int         `json:"version"`
	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
	KDF             kdfSpec     `json:"kdf"`
	PasswordWrap    sealedBlob  `json:"password_wrap"`
	ConvenienceWrap *sealedBlob `json:"convenience_wrap,omitempty"`
}

// kdfSpec captures everything OpenWithPassword needs to re-derive the wrap key:
// the algorithm name dispatches the derive function; the per-algorithm fields
// below are tagged omitempty so a pbkdf2 envelope (no Time/Memory/Parallelism)
// and an argon2id envelope (no Iterations) round-trip through JSON without
// ambiguous zero values.
type kdfSpec struct {
	Name      string `json:"name"`
	Salt      string `json:"salt"`
	KeyLength int    `json:"key_length"`

	// Iterations is the PBKDF2 iteration count. Only set when Name == "pbkdf2-sha256".
	Iterations int `json:"iterations,omitempty"`

	// Time / Memory / Parallelism are the argon2id tuning parameters from
	// RFC 9106. Only set when Name == "argon2id". Memory is in KiB.
	Time        uint32 `json:"time,omitempty"`
	Memory      uint32 `json:"memory,omitempty"`
	Parallelism uint8  `json:"parallelism,omitempty"`
}

type sealedBlob struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// appendAuditBestEffort preserves the local-first happy path when audit logging
// is temporarily unavailable. A missing logger should not turn normal brokered
// secret operations into a hard outage, but normal startup still expects audit
// log creation to succeed.
func (s *Store) appendAuditBestEffort(eventType string, actor string, details map[string]any) {
	if s == nil || s.audit == nil {
		return
	}
	_, _ = s.audit.Append(eventType, actor, details)
}
