package brokerops

import (
	"sync"
	"testing"
)

var brokeropsSeamMu sync.Mutex

func lockBrokeropsSeams(t *testing.T) {
	t.Helper()
	brokeropsSeamMu.Lock()
	t.Cleanup(brokeropsSeamMu.Unlock)
}
