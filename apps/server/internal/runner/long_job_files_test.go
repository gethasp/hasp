//go:build darwin || linux

package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLongRunningJobKeepsInjectedFileDuringLaterCleanup(t *testing.T) {
	bootstrapRunDirHomeDir(t)
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var runResult Result
	var runErr error
	go func() {
		runResult, runErr = Execute(ctx, Input{ProjectRoot: root, Files: map[string][]byte{"CERT": []byte("synthetic-certificate")}, Command: []string{"sh", "-c", `printf '%s' "$CERT" > injected-path; while [ ! -e release ]; do sleep 0.02; done; test -f "$CERT"`}})
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("child did not stop")
		}
	})
	var path []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		path, _ = os.ReadFile(filepath.Join(root, "injected-path"))
		if len(path) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(path) == 0 {
		t.Fatal("child did not open injected file")
	}
	old := time.Now().Add(-2 * staleRunDirThreshold)
	if err := os.Chtimes(filepath.Dir(string(path)), old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), Input{ProjectRoot: root, Command: []string{"true"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(string(path)); err != nil {
		t.Fatalf("a later command removed the running job's credential: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("child did not finish")
	}
	if runErr != nil || runResult.ExitCode != 0 {
		t.Fatalf("child could not use retained file: %+v, %v", runResult, runErr)
	}
}
