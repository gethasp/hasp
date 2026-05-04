package audit

import (
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestCheckpointReportsLatestSequenceAndHash(t *testing.T) {
	t.Setenv(paths.EnvHome, t.TempDir())
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	event1, err := log.Append(EventRun, "tester", map[string]any{"n": 1})
	if err != nil {
		t.Fatalf("append 1: %v", err)
	}
	event2, err := log.Append(EventRun, "tester", map[string]any{"n": 2})
	if err != nil {
		t.Fatalf("append 2: %v", err)
	}
	if event1.Sequence != 1 || event2.Sequence != 2 {
		t.Fatalf("unexpected sequences: %d %d", event1.Sequence, event2.Sequence)
	}
	checkpointSeq, checkpointHash, err := log.Checkpoint()
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if checkpointSeq != event2.Sequence || checkpointHash != event2.Hash {
		t.Fatalf("unexpected checkpoint: seq=%d hash=%s", checkpointSeq, checkpointHash)
	}
	if checkpointHash == event1.Hash {
		t.Fatalf("expected latest hash, got first hash")
	}
}
