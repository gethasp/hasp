package mcp

import (
	"sync"
	"testing"
)

var mcpSeamMu sync.Mutex

func lockMCPSeams(t *testing.T) {
	t.Helper()
	mcpSeamMu.Lock()
	t.Cleanup(mcpSeamMu.Unlock)
}
