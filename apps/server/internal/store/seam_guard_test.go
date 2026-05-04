package store

import (
	"sync"
	"testing"
)

var storeSeamMu sync.Mutex

func lockStoreSeams(t *testing.T) {
	t.Helper()
	storeSeamMu.Lock()
	t.Cleanup(storeSeamMu.Unlock)
}
