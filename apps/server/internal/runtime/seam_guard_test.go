package runtime

import (
	"sync"
	"testing"
)

var runtimeSeamMu sync.Mutex

func lockRuntimeSeams(t *testing.T) {
	t.Helper()
	runtimeSeamMu.Lock()
	t.Cleanup(runtimeSeamMu.Unlock)
}
