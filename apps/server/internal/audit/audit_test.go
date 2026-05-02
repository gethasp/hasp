package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestAppendAndVerify(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, baseDir)

	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	fixedTime := time.Date(2026, 4, 14, 0, 0, 0, 0, time.UTC)
	log.now = func() time.Time { return fixedTime }

	if _, err := log.Append(EventInit, "user", map[string]any{"version": "0.1.0"}); err != nil {
		t.Fatalf("append init: %v", err)
	}
	log.now = func() time.Time { return fixedTime.Add(time.Minute) }
	if _, err := log.Append(EventImport, "user", map[string]any{"source": ".env"}); err != nil {
		t.Fatalf("append import: %v", err)
	}
	if err := log.Verify(); err != nil {
		t.Fatalf("verify audit log: %v", err)
	}
	events, err := log.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(events) != 2 || events[0].Type != EventInit || events[1].Type != EventImport {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestEventsMissingLogAndMalformedLog(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, baseDir)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	events, err := log.Events()
	if err != nil || len(events) != 0 {
		t.Fatalf("missing events = %+v err=%v", events, err)
	}
	if err := os.MkdirAll(filepath.Dir(log.path), 0o700); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	if err := os.WriteFile(log.path, []byte("{bad-json}\n"), 0o600); err != nil {
		t.Fatalf("write malformed audit log: %v", err)
	}
	if _, err := log.Events(); err == nil {
		t.Fatal("expected malformed audit event error")
	}
	blockingFile := filepath.Join(baseDir, "blocking-file")
	if err := os.WriteFile(blockingFile, []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}
	log.path = filepath.Join(blockingFile, "audit.jsonl")
	if _, err := log.Events(); err == nil {
		t.Fatal("expected open audit log failure")
	}
	log.path = filepath.Join(baseDir, "audit-dir")
	if err := os.MkdirAll(log.path, 0o700); err != nil {
		t.Fatalf("mkdir audit dir: %v", err)
	}
	if _, err := log.Events(); err == nil {
		t.Fatal("expected scan audit directory failure")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, baseDir)

	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if _, err := log.Append(EventInit, "user", map[string]any{"version": "0.1.0"}); err != nil {
		t.Fatalf("append init: %v", err)
	}

	if err := os.WriteFile(log.path, []byte(`{"sequence":1,"timestamp":"2026-04-14T00:00:00Z","type":"init","hash":"tampered"}`+"\n"), 0o600); err != nil {
		t.Fatalf("tamper audit log: %v", err)
	}
	if err := log.Verify(); err == nil {
		t.Fatal("expected tamper detection failure")
	}
}

func TestAppendCacheInvalidatesWhenAuditFileChanges(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, baseDir)

	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := log.Append(EventRun, "tester", map[string]any{"n": i}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if _, _, err := log.Checkpoint(); err != nil {
		t.Fatalf("prime checkpoint cache: %v", err)
	}

	infoBefore, err := os.Stat(log.path)
	if err != nil {
		t.Fatalf("stat audit log: %v", err)
	}
	stateBefore := auditFileState(infoBefore)
	if stateBefore.ctimeSec == 0 && stateBefore.ctimeNsec == 0 && stateBefore.dev == 0 && stateBefore.ino == 0 {
		t.Skip("filesystem does not expose inode change state")
	}

	original, err := os.ReadFile(log.path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := bytes.SplitAfter(original, []byte("\n"))
	if len(lines) < 4 {
		t.Fatalf("expected three audit lines, got %d", len(lines)-1)
	}
	tampered := append([]byte(nil), original...)
	offset := len(lines[0])
	replacement := bytes.Repeat([]byte("x"), len(lines[1])-1)
	replacement = append(replacement, '\n')
	copy(tampered[offset:offset+len(lines[1])], replacement)

	if err := os.WriteFile(log.path, tampered, 0o600); err != nil {
		t.Fatalf("tamper audit log: %v", err)
	}
	if err := os.Chtimes(log.path, infoBefore.ModTime(), infoBefore.ModTime()); err != nil {
		t.Fatalf("restore audit mtime: %v", err)
	}
	infoAfter, err := os.Stat(log.path)
	if err != nil {
		t.Fatalf("stat tampered audit log: %v", err)
	}
	if auditFileState(infoAfter) == stateBefore {
		t.Skip("filesystem did not expose the same-size audit mutation")
	}

	if _, _, err := log.Checkpoint(); err == nil || !strings.Contains(err.Error(), "decode audit event") {
		t.Fatalf("expected checkpoint decode failure after tamper, got %v", err)
	}
	if _, err := log.Append(EventRun, "tester", nil); err == nil || !strings.Contains(err.Error(), "decode audit event") {
		t.Fatalf("expected append decode failure after tamper, got %v", err)
	}
}

func TestAppendCacheDisabledWithoutFileIdentity(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, baseDir)
	originalAuditFileState := auditFileState
	auditFileState = func(info os.FileInfo) fileState {
		return fileState{
			size:        info.Size(),
			modUnixNano: info.ModTime().UnixNano(),
		}
	}
	t.Cleanup(func() {
		auditFileState = originalAuditFileState
	})

	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if _, err := log.Append(EventRun, "tester", nil); err != nil {
		t.Fatalf("append initial: %v", err)
	}
	if seq, hash, err := log.Checkpoint(); err != nil || seq != 1 || hash == "" {
		t.Fatalf("checkpoint with fallback state: seq=%d hash=%q err=%v", seq, hash, err)
	}
	if log.cacheValid {
		t.Fatal("fallback file state must not enable the audit tail cache")
	}
	infoBefore, err := os.Stat(log.path)
	if err != nil {
		t.Fatalf("stat audit log: %v", err)
	}
	original, err := os.ReadFile(log.path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	tampered := bytes.Repeat([]byte("{"), len(original)-1)
	tampered = append(tampered, '\n')
	if err := os.WriteFile(log.path, tampered, 0o600); err != nil {
		t.Fatalf("tamper audit log: %v", err)
	}
	if err := os.Chtimes(log.path, infoBefore.ModTime(), infoBefore.ModTime()); err != nil {
		t.Fatalf("restore audit mtime: %v", err)
	}
	if _, _, err := log.Checkpoint(); err == nil || !strings.Contains(err.Error(), "decode audit event") {
		t.Fatalf("expected fallback state to rescan tampered log, got %v", err)
	}
}

func TestCheckpointCachesTailAfterColdRead(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, baseDir)

	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	event, err := log.Append(EventRun, "tester", nil)
	if err != nil {
		t.Fatalf("append initial: %v", err)
	}
	log.clearCache()
	sequence, hash, err := log.Checkpoint()
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if sequence != event.Sequence || hash != event.Hash {
		t.Fatalf("checkpoint = (%d, %q), want (%d, %q)", sequence, hash, event.Sequence, event.Hash)
	}
	if !log.cacheValid || log.cachedLast == nil || log.cachedLast.Hash != event.Hash {
		t.Fatalf("expected cold checkpoint to populate cache, valid=%v cached=%+v", log.cacheValid, log.cachedLast)
	}
}

func TestCheckpointFailsWhenAuditFileCannotBeOpened(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can open unreadable files")
	}
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, baseDir)

	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(log.path), 0o700); err != nil {
		t.Fatalf("mkdir audit dir: %v", err)
	}
	if err := os.WriteFile(log.path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}
	if err := os.Chmod(log.path, 0); err != nil {
		t.Fatalf("chmod audit log: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(log.path, 0o600) })

	if _, _, err := log.Checkpoint(); err == nil || !strings.Contains(err.Error(), "open audit log") {
		t.Fatalf("expected open audit log failure, got %v", err)
	}
}

func TestAppendCacheClearsWhenAuditFileIsRemovedOrTruncated(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, baseDir)

	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if _, err := log.Append(EventRun, "tester", nil); err != nil {
		t.Fatalf("append initial: %v", err)
	}
	if seq, hash, err := log.Checkpoint(); err != nil || seq != 1 || hash == "" {
		t.Fatalf("prime checkpoint: seq=%d hash=%q err=%v", seq, hash, err)
	}

	if err := os.Remove(log.path); err != nil {
		t.Fatalf("remove audit log: %v", err)
	}
	if seq, hash, err := log.Checkpoint(); err != nil || seq != 0 || hash != "" {
		t.Fatalf("checkpoint after remove: seq=%d hash=%q err=%v", seq, hash, err)
	}
	event, err := log.Append(EventRun, "tester", nil)
	if err != nil {
		t.Fatalf("append after remove: %v", err)
	}
	if event.Sequence != 1 || event.PrevHash != "" {
		t.Fatalf("append after remove used stale cache: seq=%d prev=%q", event.Sequence, event.PrevHash)
	}

	if err := os.Truncate(log.path, 0); err != nil {
		t.Fatalf("truncate audit log: %v", err)
	}
	if seq, hash, err := log.Checkpoint(); err != nil || seq != 0 || hash != "" {
		t.Fatalf("checkpoint after truncate: seq=%d hash=%q err=%v", seq, hash, err)
	}
	event, err = log.Append(EventRun, "tester", nil)
	if err != nil {
		t.Fatalf("append after truncate: %v", err)
	}
	if event.Sequence != 1 || event.PrevHash != "" {
		t.Fatalf("append after truncate used stale cache: seq=%d prev=%q", event.Sequence, event.PrevHash)
	}
}

func TestLogConcurrentAppendAndCheckpoint(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, baseDir)

	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				if _, err := log.Append(EventRun, "tester", map[string]any{"worker": worker, "n": i}); err != nil {
					t.Errorf("append worker=%d n=%d: %v", worker, i, err)
					return
				}
				if _, _, err := log.Checkpoint(); err != nil {
					t.Errorf("checkpoint worker=%d n=%d: %v", worker, i, err)
					return
				}
				if i%5 == 0 {
					log.WithKey(nil)
				}
			}
		}(worker)
	}
	wg.Wait()

	events, err := log.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(events) != 200 {
		t.Fatalf("event count = %d, want 200", len(events))
	}
	for i, event := range events {
		if event.Sequence != int64(i+1) {
			t.Fatalf("event %d sequence = %d", i, event.Sequence)
		}
	}
	if err := log.Verify(); err != nil {
		t.Fatalf("verify concurrent log: %v", err)
	}
}
