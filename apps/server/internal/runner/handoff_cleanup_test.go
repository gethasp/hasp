package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecuteReportsFailedCredentialCleanupAfterChildExit(t *testing.T) {
	lockRunnerSeams(t)
	_, injectRoot := bootstrapRunDirHomeDir(t)
	oldRemove := removeInjectedTree
	removeInjectedTree = func(string) error { return os.ErrPermission }
	t.Cleanup(func() { removeInjectedTree = oldRemove })
	result, err := Execute(context.Background(), Input{
		Command: []string{"sh", "-c", "test -s \"$KEY_PATH\" && printf child-completed; exit 7"},
		Files:   map[string][]byte{"KEY_PATH": []byte("synthetic-file-for-cleanup")},
	})
	if err == nil || !errors.Is(err, os.ErrPermission) || !strings.Contains(err.Error(), "cleanup") || !strings.Contains(err.Error(), "before retrying") {
		t.Fatalf("cleanup failure hidden after child execution: result=%+v err=%v", result, err)
	}
	if result.ExitCode != 7 || string(result.Stdout) != "child-completed" {
		t.Fatalf("cleanup failure lost child result: %+v", result)
	}
	entries, readErr := os.ReadDir(injectRoot)
	if readErr != nil || len(entries) != 1 {
		t.Fatalf("expected retained credential directory: %v %v", entries, readErr)
	}
	if !strings.Contains(err.Error(), filepath.Join(injectRoot, entries[0].Name())) {
		t.Fatalf("error omitted cleanup location: %v", err)
	}
}
