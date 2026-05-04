package app

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"os/user"
	goruntime "runtime"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/app/ttyutil"
	"github.com/gethasp/hasp/apps/server/internal/app/ui"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var (
	secretCurrentUserFn         = user.Current
	secretGetwdFn               = os.Getwd
	secretClipboardFn           = copySecretToClipboard
	secretExecCommandFn         = exec.Command
	secretIsCharDeviceFn        = ttyutil.IsCharDevice
	secretSetTTYEchoFn          = ttyutil.SetTTYEcho
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

	// secretRevealIsTTYFn reports whether the given writer is a terminal.
	// Tests stub this to simulate TTY / non-TTY behaviour without a real pty.
	secretRevealIsTTYFn = ui.IsInteractiveWriter
)

// Convenience aliases for the env / time constants exported by secrettypes.
// The qualified names live in production call sites that move to secretops
// in Stage 2d; tests inside package app keep using these short names.
const (
	envAgentSafeMode    = secrettypes.EnvAgentSafeMode
	envSessionToken     = secrettypes.EnvSessionToken
	envAgentConsumer    = secrettypes.EnvAgentConsumer
	envAgentProjectRoot = secrettypes.EnvAgentProjectRoot
	timeRFC3339         = secrettypes.TimeRFC3339
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

// secretMetadataView and secretMutationView are aliased to the canonical
// shapes in package secrettypes so that callers in cli_output, runtime, and
// the soon-to-move secret CLI handlers all share the same struct. The local
// names stay in place for incremental migration through Stages 2c-2d.
type secretMetadataView = secrettypes.MetadataView
type secretMutationView = secrettypes.MutationView

type secretInput struct {
	name  string
	value []byte
}
