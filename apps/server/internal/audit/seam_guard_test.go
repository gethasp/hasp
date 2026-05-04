package audit

import (
	"sync"
	"testing"
)

var auditSeamMu sync.Mutex

func lockAuditSeams(t *testing.T) {
	t.Helper()
	auditSeamMu.Lock()
	t.Cleanup(auditSeamMu.Unlock)
}
