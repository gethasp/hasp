package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

var resolveJobPaths = paths.Resolve

func jobFingerprint(command []string, env, files, literals map[string]string, workingDir, manifestHash string) string {
	data, _ := json.Marshal(struct {
		Command                  []string
		Env, Files, Literals     map[string]string
		WorkingDir, ManifestHash string
	}{command, env, files, literals, workingDir, manifestHash})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func connectJobDaemon(ctx context.Context) (*runtime.Client, error) {
	resolved, err := resolveJobPaths()
	if err != nil {
		return nil, err
	}
	return runtime.Dial(ctx, resolved.SocketPath)
}

func jobPayload(status runtime.JobStatus) map[string]any {
	data, _ := json.Marshal(status)
	var result map[string]any
	_ = json.Unmarshal(data, &result)
	return result
}

func callJobStatus(ctx context.Context, call toolCall) (map[string]any, error) {
	root, err := canonicalProjectRootMCPFn(ctx, stringArg(call.Arguments, "project_root", defaultMCPProjectRoot()))
	if err != nil {
		return nil, err
	}
	session, err := ensureMCPSession(ctx, call, root)
	if err != nil {
		return nil, err
	}
	id := stringArg(call.Arguments, "job_id", "")
	requestID := stringArg(call.Arguments, "request_id", "")
	if id != "" && requestID != "" {
		return nil, errors.New("provide job_id or request_id, not both")
	}
	if id == "" {
		id, err = runtime.JobID(root, requestID)
		if err != nil {
			return nil, err
		}
	}
	stdoutOffset, err := jobOffset(call.Arguments, "stdout_offset")
	if err != nil {
		return nil, err
	}
	stderrOffset, err := jobOffset(call.Arguments, "stderr_offset")
	if err != nil {
		return nil, err
	}
	client, err := connectJobDaemon(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	query := runtime.JobQuery{SessionToken: session.Token, ProjectRoot: root, JobID: id, StdoutOffset: stdoutOffset, StderrOffset: stderrOffset}
	var status runtime.JobStatus
	if call.Name == "hasp_job_cancel" {
		status, err = client.CancelJob(ctx, query)
	} else {
		status, err = client.GetJob(ctx, query)
	}
	if err != nil {
		return nil, err
	}
	return jobPayload(status), nil
}

func jobOffset(args map[string]any, key string) (int64, error) {
	value, exists := args[key]
	if !exists {
		return 0, nil
	}
	number, ok := value.(float64)
	if !ok || number < 0 || number > 1<<53 || float64(int64(number)) != number {
		return 0, fmt.Errorf("%s must be a non-negative byte offset returned by job status", key)
	}
	return int64(number), nil
}
