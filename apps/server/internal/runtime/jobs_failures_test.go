package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestJobStartRejectsInvalidAndUnavailableRequests(t *testing.T) {
	for _, step := range []string{"request ID", "command", "fingerprint", "closed", "capacity", "reservation"} {
		t.Run(step, func(t *testing.T) {
			s := newJobStore(t.TempDir())
			req := JobStartRequest{ProjectRoot: t.TempDir(), RequestID: strings.Repeat("a", 32), Fingerprint: strings.Repeat("b", 64), Command: []string{"sh", "-c", "touch executed"}}
			switch step {
			case "request ID":
				req.RequestID = "invalid"
			case "command":
				req.Command = nil
			case "fingerprint":
				req.Fingerprint = "invalid"
			case "closed":
				s.closed = true
			case "capacity":
				for i := range maxActiveJobs {
					s.active[strconv.Itoa(i)] = &brokerJob{}
				}
			case "reservation":
				if err := os.Mkdir(s.dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(s.dir, 0o777); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.start(req); err == nil {
				t.Fatalf("%s permitted launch", step)
			}
			if _, err := os.Stat(filepath.Join(req.ProjectRoot, "executed")); !os.IsNotExist(err) {
				t.Fatalf("rejected request started child: %v", err)
			}
		})
	}
}

func TestJobReceiptReadErrorsBlockCancellationAndReplay(t *testing.T) {
	s := newJobStore(t.TempDir())
	if _, err := s.get(JobQuery{JobID: "invalid"}); err == nil {
		t.Fatal("invalid handle accepted")
	}
	if _, err := s.cancelJob(JobQuery{JobID: "invalid"}); err == nil {
		t.Fatal("invalid cancellation accepted")
	}
	query := JobQuery{JobID: strings.Repeat("a", 64)}
	s.dir = "\x00"
	if _, err := s.get(query); err == nil {
		t.Fatal("receipt open error ignored")
	}
	s.dir = t.TempDir()
	if err := os.Mkdir(filepath.Join(s.dir, query.JobID+".json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.get(query); err == nil {
		t.Fatal("receipt read error ignored")
	}
}

func TestJobReceiptWriteFailuresRemainErrors(t *testing.T) {
	lockRuntimeSeams(t)
	originalLstat, originalSync, originalClose, originalOpen := jobReceiptLstat, jobReceiptSync, jobReceiptClose, jobReceiptOpenDir
	t.Cleanup(func() {
		jobReceiptLstat, jobReceiptSync, jobReceiptClose, jobReceiptOpenDir = originalLstat, originalSync, originalClose, originalOpen
	})
	for _, step := range []string{"mkdir", "lstat", "sync", "close", "rename", "open directory"} {
		jobReceiptLstat, jobReceiptSync, jobReceiptClose, jobReceiptOpenDir = originalLstat, originalSync, originalClose, originalOpen
		s := newJobStore(t.TempDir())
		record := jobRecord{JobStatus: JobStatus{JobID: strings.Repeat("a", 64), State: "completed"}}
		switch step {
		case "mkdir":
			if err := os.WriteFile(s.dir, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		case "lstat":
			jobReceiptLstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
		case "sync":
			jobReceiptSync = func(*os.File) error { return os.ErrPermission }
		case "close":
			jobReceiptClose = func(file *os.File) error { _ = file.Close(); return os.ErrPermission }
		case "rename":
			if err := os.MkdirAll(filepath.Join(s.dir, record.JobID+".json"), 0o700); err != nil {
				t.Fatal(err)
			}
		case "open directory":
			jobReceiptOpenDir = func(string) (*os.File, error) { return nil, os.ErrPermission }
		}
		if err := s.persist(record); err == nil {
			t.Fatalf("%s failure ignored", step)
		}
		entries, _ := os.ReadDir(s.dir)
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".receipt-") {
				t.Fatalf("%s left temporary receipt %s", step, entry.Name())
			}
		}
	}
}

func TestJobFailedFinalReceiptRetainsCompletedStatus(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	s := newJobStore(t.TempDir())
	if err := os.WriteFile(s.dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	job := &brokerJob{record: jobRecord{JobStatus: JobStatus{JobID: strings.Repeat("a", 64)}, ProjectRoot: t.TempDir()}, cancel: cancel, done: make(chan struct{})}
	s.active[job.record.JobID] = job
	s.run(ctx, job, JobStartRequest{ProjectRoot: job.record.ProjectRoot, Command: []string{"sh", "-c", "printf complete"}})
	select {
	case <-job.done:
	default:
		t.Fatal("completed worker did not signal completion")
	}
	status, err := s.get(JobQuery{ProjectRoot: job.record.ProjectRoot, JobID: job.record.JobID})
	if err != nil || status.State != "completed" || status.ExitCode == nil || *status.ExitCode != 0 || status.Stdout != "complete" || !strings.Contains(status.Error, "final receipt could not be saved") {
		t.Fatalf("lost final status: %+v, %v", status, err)
	}
	if s.active[job.record.JobID] != job {
		t.Fatal("failed persistence discarded in-memory receipt")
	}
	s.stop()
}

func TestJobOutputKeepsTailOfSingleOversizedWrite(t *testing.T) {
	job := &brokerJob{}
	value := strings.Repeat("x", jobOutputLimit) + "tail"
	n, err := (jobWriter{job: job}).Write([]byte(value))
	if err != nil || n != len(value) || len(job.record.Stdout) != jobOutputLimit || !strings.HasSuffix(job.record.Stdout, "tail") {
		t.Fatalf("tail length=%d write=%d err=%v", len(job.record.Stdout), n, err)
	}
	got, omitted := jobOutputSince(job.record.Stdout, job.record.StdoutOffset, -1)
	if got != job.record.Stdout || omitted != 4 {
		t.Fatalf("negative cursor: length=%d omitted=%d", len(got), omitted)
	}
}

func TestJobRPCStartAndCancelRequireServiceAndSession(t *testing.T) {
	var status JobStatus
	b := &brokerRPC{}
	if err := b.StartJob(JobStartRequest{}, &status); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing service: %v", err)
	}
	b.jobs, b.sessions = newJobStore(t.TempDir()), NewSessionStore()
	if err := b.CancelJob(JobQuery{}, &status); err == nil || !strings.Contains(err.Error(), "session not found") {
		t.Fatalf("missing session: %v", err)
	}
	session, err := b.sessions.Open("test", t.TempDir(), time.Minute, true, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.StartJob(JobStartRequest{SessionToken: session.Token, ProjectRoot: t.TempDir()}, &status); err == nil {
		t.Fatal("wrong project accepted")
	}
	if err := b.CancelJob(JobQuery{SessionToken: session.Token, ProjectRoot: t.TempDir()}, &status); err == nil {
		t.Fatal("wrong project cancellation accepted")
	}
}
