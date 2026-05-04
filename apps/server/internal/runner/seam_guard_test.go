package runner

import (
	"sync"
	"testing"
)

var runnerSeamMu sync.Mutex

func lockRunnerSeams(t *testing.T) {
	t.Helper()
	runnerSeamMu.Lock()
	t.Cleanup(runnerSeamMu.Unlock)
}
