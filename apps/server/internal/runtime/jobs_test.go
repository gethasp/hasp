package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestJobConcurrentStartAndCrashReceiptNeverReplay(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	root := t.TempDir()
	s := newJobStore(t.TempDir())
	t.Cleanup(s.stop)
	req := JobStartRequest{ProjectRoot: root, RequestID: "a11c55fedf334f13b8b09caf007e6229", Fingerprint: strings.Repeat("1", 64), Command: []string{"sh", "-c", "printf x >> executions"}}
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if _, err := s.start(req); err != nil {
				t.Error(err)
			}
		}()
	}
	workers.Wait()
	id, _ := JobID(root, req.RequestID)
	query := JobQuery{ProjectRoot: root, JobID: id}
	pollJob(t, s, query, func(status JobStatus) bool { return status.State == "completed" })
	marker, err := os.ReadFile(filepath.Join(root, "executions"))
	if err != nil || string(marker) != "x" {
		t.Fatalf("duplicate launch: %q, %v", marker, err)
	}
	// A durable running receipt with no live daemon worker is an uncertain
	// outcome. It must prevent another start even though no result was saved.
	req.RequestID = "cd68730e59c54b18a54cac1ebd3be742"
	id, _ = JobID(root, req.RequestID)
	if err := s.persist(jobRecord{JobStatus: JobStatus{JobID: id, State: "running", StartedAt: time.Now()}, ProjectRoot: root, Fingerprint: req.Fingerprint}); err != nil {
		t.Fatal(err)
	}
	afterRestart := newJobStore(filepath.Dir(s.dir))
	status, err := afterRestart.start(req)
	if err != nil || status.State != "interrupted" {
		t.Fatalf("uncertain job was replayed: %+v, %v", status, err)
	}
	marker, _ = os.ReadFile(filepath.Join(root, "executions"))
	if string(marker) != "x" {
		t.Fatal("crash recovery replayed the child")
	}
}

func TestJobOutputIsBoundedRedactedAndPersistedWithoutInputs(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	root := t.TempDir()
	s := newJobStore(t.TempDir())
	t.Cleanup(s.stop)
	secret := "test-secret-that-must-not-be-saved"
	req := JobStartRequest{ProjectRoot: root, RequestID: "d54cc0d8832a4edcae56878782c50288", Fingerprint: strings.Repeat("2", 64), Env: map[string]string{"TOKEN": secret}, Items: []store.Item{{Name: "token", Value: []byte(secret)}}, Command: []string{"sh", "-c", `printf '%s\n' "$TOKEN"; printf '%070000d' 0; printf '%s\n' "$TOKEN" >&2`}}
	first, err := s.start(req)
	if err != nil {
		t.Fatal(err)
	}
	final := pollJob(t, s, JobQuery{ProjectRoot: root, JobID: first.JobID}, func(status JobStatus) bool { return status.State == "completed" })
	if len(final.Stdout) > jobOutputLimit || final.StdoutBytesOmitted == 0 || !final.Redacted || strings.Contains(final.Stdout+final.Stderr, secret) {
		t.Fatalf("unbounded or unredacted output: lengths=%d/%d, omitted=%d, redacted=%t", len(final.Stdout), len(final.Stderr), final.StdoutBytesOmitted, final.Redacted)
	}
	query := JobQuery{ProjectRoot: root, JobID: first.JobID, StdoutOffset: final.StdoutOffset, StderrOffset: final.StderrOffset}
	next, err := s.get(query)
	if err != nil || next.Stdout != "" || next.Stderr != "" {
		t.Fatalf("offset replay returned old bytes: %+v, %v", next, err)
	}
	data, err := os.ReadFile(filepath.Join(s.dir, first.JobID+".json"))
	if err != nil || strings.Contains(string(data), secret) || strings.Contains(string(data), "TOKEN") {
		t.Fatalf("receipt persisted raw job input or secret (read error %v)", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exists := fields["command"]; exists {
		t.Fatal("receipt persisted command argv")
	}
	info, _ := os.Stat(filepath.Join(s.dir, first.JobID+".json"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt mode %v", info.Mode())
	}
}

func TestJobSeparateDaemonsShareOneDurableReservation(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	root, runtimeDir := t.TempDir(), t.TempDir()
	req := JobStartRequest{ProjectRoot: root, RequestID: "acd5ba0a09e847b8a03625cab048b2bc", Fingerprint: strings.Repeat("3", 64), Command: []string{"sh", "-c", "printf x >> executions"}}
	stores := make([]*jobStore, 8)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := range stores {
		stores[i] = newJobStore(runtimeDir)
		t.Cleanup(stores[i].stop)
		workers.Add(1)
		go func(s *jobStore) { defer workers.Done(); <-start; _, _ = s.start(req) }(stores[i])
	}
	close(start)
	workers.Wait()
	for _, s := range stores {
		s.mu.Lock()
		var pending []*brokerJob
		for _, job := range s.active {
			pending = append(pending, job)
		}
		s.mu.Unlock()
		for _, job := range pending {
			select {
			case <-job.done:
			case <-time.After(3 * time.Second):
				t.Fatal("job did not finish")
			}
		}
	}
	marker, err := os.ReadFile(filepath.Join(root, "executions"))
	if err != nil || string(marker) != "x" {
		t.Fatalf("separate daemons replayed a request: %q, %v", marker, err)
	}
}

func TestJobUnreadableReceiptBlocksReplay(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	root := t.TempDir()
	s := newJobStore(t.TempDir())
	req := JobStartRequest{ProjectRoot: root, RequestID: "af3147cb27fa45238c98a0665d96874a", Fingerprint: strings.Repeat("4", 64), Command: []string{"sh", "-c", "touch executed"}}
	id, _ := JobID(root, req.RequestID)
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, id+".json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.start(req); err == nil || !strings.Contains(err.Error(), "do not replay") {
		t.Fatalf("bad receipt permitted replay: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "executed")); !os.IsNotExist(err) {
		t.Fatal("child ran after unreadable receipt")
	}
}

func TestJobSpawnFailureHasNoChildExitCode(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	root := t.TempDir()
	s := newJobStore(t.TempDir())
	t.Cleanup(s.stop)
	req := JobStartRequest{ProjectRoot: root, RequestID: "e213f45ecc3c4620ad925a9a9a80dddc", Fingerprint: strings.Repeat("5", 64), Command: []string{filepath.Join(root, "missing-command")}}
	first, err := s.start(req)
	if err != nil {
		t.Fatal(err)
	}
	final := pollJob(t, s, JobQuery{ProjectRoot: root, JobID: first.JobID}, func(status JobStatus) bool { return status.State == "failed" })
	if final.ExitCode != nil || final.Error == "" {
		t.Fatalf("spawn failure looked like child exit: %+v", final)
	}
}

func TestJobInheritsCallerEnvironmentAndFiltersInternalSecrets(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("JOB_CONTEXT", "daemon")
	root := t.TempDir()
	s := newJobStore(t.TempDir())
	t.Cleanup(s.stop)
	req := JobStartRequest{ProjectRoot: root, RequestID: "487776bd390945968bf41a44d8a29e06", Fingerprint: strings.Repeat("6", 64), ParentEnv: []string{"PATH=" + os.Getenv("PATH"), "JOB_CONTEXT=caller", "HASP_MASTER_PASSWORD=must-be-filtered", "HASP_SESSION_TOKEN=must-be-filtered"}, Command: []string{"sh", "-c", `test "$JOB_CONTEXT" = caller && test -z "$HASP_MASTER_PASSWORD" && test -z "$HASP_SESSION_TOKEN"`}}
	first, err := s.start(req)
	if err != nil {
		t.Fatal(err)
	}
	final := pollJob(t, s, JobQuery{ProjectRoot: root, JobID: first.JobID}, func(status JobStatus) bool { return status.State == "completed" })
	if final.ExitCode == nil || *final.ExitCode != 0 {
		t.Fatalf("job changed the caller's execution environment: %+v", final)
	}
}

func TestJobRPCRejectsMissingAndWrongProjectSessions(t *testing.T) {
	sessions := NewSessionStore()
	b := &brokerRPC{sessions: sessions, jobs: newJobStore(t.TempDir())}
	var status JobStatus
	if err := b.GetJob(JobQuery{SessionToken: "missing", ProjectRoot: t.TempDir()}, &status); err == nil {
		t.Fatal("missing session accepted")
	}
	session, err := sessions.Open("job-test", t.TempDir(), time.Minute, true, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.GetJob(JobQuery{SessionToken: session.Token, ProjectRoot: t.TempDir()}, &status); err == nil || !strings.Contains(err.Error(), "project root mismatch") {
		t.Fatalf("wrong project accepted: %v", err)
	}
}

func pollJob(t *testing.T, s *jobStore, query JobQuery, ready func(JobStatus) bool) JobStatus {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status, err := s.get(query)
		if err != nil {
			t.Fatal(err)
		}
		if ready(status) {
			return status
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return JobStatus{}
}
