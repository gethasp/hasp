package app

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"os/user"
	goruntime "runtime"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var (
	secretCurrentUserFn         = user.Current
	secretGetwdFn               = os.Getwd
	secretClipboardFn           = copySecretToClipboard
	secretExecCommandFn         = exec.Command
	secretIsCharDeviceFn        = isCharDevice
	secretSetTTYEchoFn          = secretSetTTYEcho
	secretRuntimeGOOS           = goruntime.GOOS
	secretUpsertItemFn          = (*store.Handle).UpsertItem
	secretGetItemFn             = (*store.Handle).GetItem
	secretDeleteItemFn          = (*store.Handle).DeleteItem
	secretListItemsFn           = (*store.Handle).ListItems
	secretListAgentsFn          = (*store.Handle).ListAgentConsumers
	secretBindItemAliasFn       = (*store.Handle).BindItemAlias
	secretHideItemFn            = (*store.Handle).HideItemFromProject
	secretItemExposuresFn       = (*store.Handle).ItemExposures
	secretRevokeGrantsForItemFn = (*store.Handle).RevokeGrantsForItem
	secretNewManagerFn          = runtime.NewManager
	secretDialRuntimeFn         = runtime.Dial
)

const (
	envAgentSafeMode    = "HASP_AGENT_SAFE_MODE"
	envSessionToken     = "HASP_SESSION_TOKEN"
	envAgentConsumer    = "HASP_AGENT_CONSUMER"
	envAgentProjectRoot = "HASP_AGENT_PROJECT_ROOT"
	timeRFC3339         = "2006-01-02T15:04:05Z07:00"
)

type secretPlaintextPolicy struct {
	Active         bool
	Source         string
	SessionToken   string
	ProjectRoot    string
	AgentConsumers []string
}

type secretPrompt struct {
	reader *bufio.Reader
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

type secretMetadataView struct {
	Name           string               `json:"name"`
	NamedReference string               `json:"named_reference,omitempty"`
	Kind           store.ItemKind       `json:"kind"`
	CreatedAt      string               `json:"created_at"`
	UpdatedAt      string               `json:"updated_at"`
	Exposures      []store.ItemExposure `json:"exposures"`
}

type secretMutationView struct {
	Name           string               `json:"name"`
	NamedReference string               `json:"named_reference,omitempty"`
	Kind           store.ItemKind       `json:"kind,omitempty"`
	Outcome        string               `json:"outcome"`
	ProjectRoot    string               `json:"project_root,omitempty"`
	Reference      string               `json:"reference,omitempty"`
	Exposures      []store.ItemExposure `json:"exposures,omitempty"`
}

type secretInput struct {
	name  string
	value []byte
}
