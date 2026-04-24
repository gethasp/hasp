package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	// Tests create and open many ephemeral vaults across multiple packages.
	// Using a lower derivation cost only inside `go test` keeps the default
	// parallel suite stable without changing production envelopes.
	passwordIterations = derivePasswordIterations(filepath.Base(os.Args[0]))
)

func derivePasswordIterations(binaryName string) int {
	if strings.HasSuffix(strings.TrimSpace(binaryName), ".test") {
		return testPasswordIterations
	}
	return productionPasswordIterations
}

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

type kdfSpec struct {
	Name       string `json:"name"`
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	KeyLength  int    `json:"key_length"`
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
