package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/redactor"
	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

const jobOutputLimit = 64 << 10
const maxActiveJobs = 16

var (
	jobReceiptLstat   = os.Lstat
	jobReceiptSync    = (*os.File).Sync
	jobReceiptClose   = (*os.File).Close
	jobReceiptOpenDir = os.Open
)

// JobRequestID is a client-generated 128-bit hex nonce, retained for retries.
// The derived handle permits observing or cancelling only this execution.
func JobID(root, requestID string) (string, error) {
	b, err := hex.DecodeString(requestID)
	if err != nil || len(b) != 16 {
		return "", errors.New("request_id must be a new random 32-character hexadecimal ID; reuse it only to recover the same command")
	}
	sum := sha256.Sum256([]byte(root + "\x00" + strings.ToLower(requestID)))
	return hex.EncodeToString(sum[:]), nil
}

type JobStartRequest struct {
	SessionToken string
	ProjectRoot  string
	WorkingDir   string
	RequestID    string
	Fingerprint  string
	Command      []string
	Env          map[string]string
	Files        map[string][]byte
	Items        []store.Item
	ParentEnv    []string
}

type JobQuery struct {
	SessionToken string
	ProjectRoot  string
	JobID        string
	Fingerprint  string
	StdoutOffset int64
	StderrOffset int64
}

type JobStatus struct {
	JobID              string     `json:"job_id"`
	State              string     `json:"state"`
	StartedAt          time.Time  `json:"started_at"`
	FinishedAt         *time.Time `json:"finished_at,omitempty"`
	ExitCode           *int       `json:"exit_code,omitempty"`
	Error              string     `json:"error,omitempty"`
	Stdout             string     `json:"stdout"`
	Stderr             string     `json:"stderr"`
	StdoutOffset       int64      `json:"stdout_offset"`
	StderrOffset       int64      `json:"stderr_offset"`
	StdoutBytesOmitted int64      `json:"stdout_bytes_omitted"`
	StderrBytesOmitted int64      `json:"stderr_bytes_omitted"`
	Redacted           bool       `json:"redacted"`
}

type jobRecord struct {
	JobStatus
	ProjectRoot string `json:"project_root"`
	Fingerprint string `json:"fingerprint"`
}

type brokerJob struct {
	mu     sync.Mutex
	record jobRecord
	cancel context.CancelFunc
	done   chan struct{}
}

type jobStore struct {
	mu     sync.Mutex
	dir    string
	active map[string]*brokerJob
	closed bool
}

func newJobStore(runtimeDir string) *jobStore {
	return &jobStore{dir: filepath.Join(runtimeDir, "jobs"), active: make(map[string]*brokerJob)}
}

func (s *jobStore) start(req JobStartRequest) (JobStatus, error) {
	id, err := JobID(req.ProjectRoot, req.RequestID)
	if err != nil {
		return JobStatus{}, err
	}
	if len(req.Command) == 0 || len(req.Fingerprint) != 64 {
		return JobStatus{}, errors.New("command and request fingerprint are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return JobStatus{}, errors.New("daemon is stopping; recover this request after reconnecting")
	}
	if existing, err := s.getLocked(JobQuery{ProjectRoot: req.ProjectRoot, JobID: id, Fingerprint: req.Fingerprint}); err != nil || existing.State != "not_found" {
		return existing, err
	}
	if len(s.active) >= maxActiveJobs {
		return JobStatus{}, errors.New("16 jobs are already running; poll or cancel an existing job before starting another")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	job := &brokerJob{record: jobRecord{JobStatus: JobStatus{JobID: id, State: "running", StartedAt: time.Now().UTC()}, ProjectRoot: req.ProjectRoot, Fingerprint: req.Fingerprint}, cancel: cancel, done: make(chan struct{})}
	// Persist the receipt before launching. Even a lost RPC response or daemon
	// crash cannot cause the same request to launch a second child.
	if err := s.reserve(job.record); errors.Is(err, os.ErrExist) {
		cancel()
		return s.getLocked(JobQuery{ProjectRoot: req.ProjectRoot, JobID: id, Fingerprint: req.Fingerprint})
	} else if err != nil {
		cancel()
		return JobStatus{}, err
	}
	s.active[id] = job
	initial := job.record.JobStatus
	go s.run(ctx, job, req)
	return initial, nil
}

func (s *jobStore) run(ctx context.Context, job *brokerJob, req JobStartRequest) {
	defer job.cancel()
	stdout := &jobStream{redactor.NewStreamingWriterANSIAware(jobWriter{job, false}, req.Items), job}
	stderr := &jobStream{redactor.NewStreamingWriterANSIAware(jobWriter{job, true}, req.Items), job}
	workingDir := req.WorkingDir
	if workingDir == "" {
		workingDir = req.ProjectRoot
	}
	result, err := runner.Execute(ctx, runner.Input{ProjectRoot: workingDir, Command: req.Command, Env: req.Env, Files: req.Files, ParentEnv: req.ParentEnv, Stdout: stdout, Stderr: stderr, ProcessGroup: true})
	_ = stdout.Flush()
	_ = stderr.Flush()
	job.mu.Lock()
	finished := time.Now().UTC()
	job.record.FinishedAt = &finished
	if err == nil {
		job.record.ExitCode = &result.ExitCode
	}
	job.record.Redacted = stdout.Stats().Redacted || stderr.Stats().Redacted
	switch {
	case ctx.Err() != nil:
		job.record.State = "cancelled"
		job.record.Error = ctx.Err().Error()
	case err != nil:
		job.record.State = "failed"
		job.record.ExitCode = nil
		job.record.Error = string(redactor.Apply([]byte(err.Error()), req.Items).Output)
	default:
		job.record.State = "completed"
	}
	persistErr := s.persist(job.record)
	if persistErr != nil {
		job.record.Error = "final receipt could not be saved; after daemon restart the outcome will be unknown"
		// Retain the in-memory final status until shutdown if persistence failed.
	}
	job.mu.Unlock()
	if persistErr == nil {
		s.mu.Lock()
		delete(s.active, job.record.JobID)
		s.mu.Unlock()
	}
	close(job.done)
}

type jobWriter struct {
	job    *brokerJob
	stderr bool
}

type jobStream struct {
	*redactor.StreamingWriter
	job *brokerJob
}

func (s *jobStream) Write(p []byte) (int, error) {
	n, err := s.StreamingWriter.Write(p)
	if s.Stats().Redacted {
		s.job.mu.Lock()
		s.job.record.Redacted = true
		s.job.mu.Unlock()
	}
	return n, err
}

func (w jobWriter) Write(p []byte) (int, error) {
	w.job.mu.Lock()
	defer w.job.mu.Unlock()
	output, offset := &w.job.record.Stdout, &w.job.record.StdoutOffset
	if w.stderr {
		output, offset = &w.job.record.Stderr, &w.job.record.StderrOffset
	}
	*offset += int64(len(p))
	if len(p) >= jobOutputLimit {
		*output = string(p[len(p)-jobOutputLimit:])
	} else {
		keep := jobOutputLimit - len(p)
		if len(*output) > keep {
			*output = (*output)[len(*output)-keep:]
		}
		*output += string(p)
	}
	return len(p), nil
}

func (s *jobStore) get(req JobQuery) (JobStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(req)
}

func (s *jobStore) getLocked(req JobQuery) (JobStatus, error) {
	if !validJobID(req.JobID) {
		return JobStatus{}, errors.New("job_id must be the handle returned by hasp_job_start")
	}
	var record jobRecord
	if job := s.active[req.JobID]; job != nil {
		job.mu.Lock()
		record = job.record
		job.mu.Unlock()
	} else {
		file, err := os.Open(filepath.Join(s.dir, req.JobID+".json"))
		if errors.Is(err, os.ErrNotExist) {
			return JobStatus{JobID: req.JobID, State: "not_found"}, nil
		}
		if err != nil {
			return JobStatus{}, err
		}
		data, err := io.ReadAll(io.LimitReader(file, 1<<20))
		_ = file.Close()
		if err != nil {
			return JobStatus{}, err
		}
		if err := json.Unmarshal(data, &record); err != nil {
			return JobStatus{}, fmt.Errorf("job receipt is unreadable; do not replay the command: %w", err)
		}
		if record.State == "running" {
			record.State = "interrupted"
			record.Error = "no running worker is attached to this daemon and no final result was saved; outcome unknown; this request will not be replayed"
		}
	}
	if record.ProjectRoot != req.ProjectRoot {
		return JobStatus{}, errors.New("job belongs to a different project")
	}
	if req.Fingerprint != "" && req.Fingerprint != record.Fingerprint {
		return JobStatus{}, errors.New("request_id was already used for a different command; inspect the existing job and choose a new ID only for new work")
	}
	out := record.JobStatus
	out.Stdout, out.StdoutBytesOmitted = jobOutputSince(out.Stdout, out.StdoutOffset, req.StdoutOffset)
	out.Stderr, out.StderrBytesOmitted = jobOutputSince(out.Stderr, out.StderrOffset, req.StderrOffset)
	return out, nil
}

func jobOutputSince(tail string, end, after int64) (string, int64) {
	start := end - int64(len(tail))
	if after < 0 {
		after = 0
	}
	if after >= end {
		return "", 0
	}
	if after < start {
		return tail, start - after
	}
	return tail[after-start:], 0
}

func (s *jobStore) cancelJob(req JobQuery) (JobStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	status, err := s.getLocked(req)
	if err != nil {
		return JobStatus{}, err
	}
	if job := s.active[req.JobID]; job != nil {
		job.cancel()
		status.State = "cancelling"
	}
	return status, nil
}

func (s *jobStore) stop() {
	s.mu.Lock()
	s.closed = true
	jobs := make([]*brokerJob, 0, len(s.active))
	for _, job := range s.active {
		job.cancel()
		jobs = append(jobs, job)
	}
	s.mu.Unlock()
	for _, job := range jobs {
		<-job.done
	}
}

func validJobID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == sha256.Size
}

func (s *jobStore) persist(record jobRecord) error {
	return s.writeRecord(record, false)
}

func (s *jobStore) reserve(record jobRecord) error {
	return s.writeRecord(record, true)
}

func (s *jobStore) writeRecord(record jobRecord, exclusive bool) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	info, err := jobReceiptLstat(s.dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("job receipt directory must be a private directory")
	}
	var file *os.File
	if exclusive {
		file, err = os.OpenFile(filepath.Join(s.dir, record.JobID+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	} else {
		file, err = os.CreateTemp(s.dir, ".receipt-")
	}
	if err != nil {
		return err
	}
	// Keep a failed initial write as a reservation. Its uncertain outcome
	// must not become permission to launch again on another daemon connection.
	if !exclusive {
		defer os.Remove(file.Name())
	}
	if err = json.NewEncoder(file).Encode(record); err == nil {
		err = jobReceiptSync(file)
	}
	closeErr := jobReceiptClose(file)
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if !exclusive {
		if err := os.Rename(file.Name(), filepath.Join(s.dir, record.JobID+".json")); err != nil {
			return err
		}
	}
	dir, err := jobReceiptOpenDir(s.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return jobReceiptSync(dir)
}

func (b *brokerRPC) checkJobSession(token, root string) error {
	if b.jobs == nil {
		return errors.New("job service unavailable")
	}
	session, ok := b.sessions.Resolve(token)
	if !ok {
		return errors.New("session not found")
	}
	if session.ProjectRoot != root {
		return errors.New("project root mismatch")
	}
	return nil
}

func (b *brokerRPC) StartJob(req JobStartRequest, reply *JobStatus) error {
	if err := b.checkJobSession(req.SessionToken, req.ProjectRoot); err != nil {
		return err
	}
	status, err := b.jobs.start(req)
	*reply = status
	return err
}

func (b *brokerRPC) GetJob(req JobQuery, reply *JobStatus) error {
	if err := b.checkJobSession(req.SessionToken, req.ProjectRoot); err != nil {
		return err
	}
	status, err := b.jobs.get(req)
	*reply = status
	return err
}

func (b *brokerRPC) CancelJob(req JobQuery, reply *JobStatus) error {
	if err := b.checkJobSession(req.SessionToken, req.ProjectRoot); err != nil {
		return err
	}
	status, err := b.jobs.cancelJob(req)
	*reply = status
	return err
}

func (c *Client) StartJob(ctx context.Context, req JobStartRequest) (JobStatus, error) {
	var reply JobStatus
	err := c.call(ctx, "HASP.StartJob", req, &reply)
	return reply, err
}
func (c *Client) GetJob(ctx context.Context, req JobQuery) (JobStatus, error) {
	var reply JobStatus
	err := c.call(ctx, "HASP.GetJob", req, &reply)
	return reply, err
}
func (c *Client) CancelJob(ctx context.Context, req JobQuery) (JobStatus, error) {
	var reply JobStatus
	err := c.call(ctx, "HASP.CancelJob", req, &reply)
	return reply, err
}

var _ io.Writer = jobWriter{}
