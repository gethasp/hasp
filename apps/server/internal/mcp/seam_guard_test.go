package mcp

import (
	"sync"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/auditlog"
)

var mcpSeamMu sync.Mutex

func lockMCPSeams(t *testing.T) {
	t.Helper()
	mcpSeamMu.Lock()
	auditlog.ClearHMACKey()
	t.Cleanup(func() {
		auditlog.ClearHMACKey()
		mcpSeamMu.Unlock()
	})
}
