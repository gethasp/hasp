package app

import (
	"sync"
	"testing"
)

var appSeamMu sync.Mutex

func lockAppSeams(t *testing.T) {
	t.Helper()
	appSeamMu.Lock()
	t.Cleanup(appSeamMu.Unlock)
}
