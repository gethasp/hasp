package main

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func TestRunSuccessPath(t *testing.T) {
	var stdout bytes.Buffer
	code := run(context.Background(), []string{"help"}, bytes.NewBuffer(nil), &stdout, &stdout)
	if code != 0 {
		t.Fatalf("run returned code %d", code)
	}
	if stdout.Len() == 0 {
		t.Fatal("expected help output")
	}
}

func TestRunFailurePath(t *testing.T) {
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"does-not-exist"}, bytes.NewBuffer(nil), &stderr, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if stderr.Len() == 0 {
		t.Fatal("expected error output")
	}
}

func TestMainUsesExitFn(t *testing.T) {
	origArgs := os.Args
	origExit := exitFn
	defer func() {
		os.Args = origArgs
		exitFn = origExit
	}()

	var code int
	exitFn = func(v int) { code = v }
	os.Args = []string{"hasp", "help"}
	main()
	if code != 0 {
		t.Fatalf("main exit code = %d, want 0", code)
	}
}
