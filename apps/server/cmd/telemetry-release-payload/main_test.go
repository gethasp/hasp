package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/telemetry"
)

func TestRunPrintsEndpoint(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := run([]string{"--endpoint"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run exit = %d, want 0", code)
	}
	if got := strings.TrimSpace(stdout.String()); got != telemetry.TrustedEndpoint {
		t.Fatalf("endpoint = %q, want %q", got, telemetry.TrustedEndpoint)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunRejectsUnexpectedArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := run([]string{"extra"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run exit = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "usage: telemetry-release-payload") {
		t.Fatalf("stderr = %q, want usage", stderr.String())
	}
}

func TestRunWritesReleasePayload(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := run(nil, &stdout, &stderr); code != 0 {
		t.Fatalf("run exit = %d, want 0; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"hasp_version":"release-gate"`) {
		t.Fatalf("payload = %q, want release gate version", stdout.String())
	}
	if !strings.HasSuffix(stdout.String(), "\n") {
		t.Fatal("payload should end with newline")
	}
}

func TestRunReportsPayloadErrors(t *testing.T) {
	orig := releaseGatePayloadFn
	t.Cleanup(func() { releaseGatePayloadFn = orig })
	releaseGatePayloadFn = func() ([]byte, error) { return nil, errors.New("payload failed") }

	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 1 {
		t.Fatalf("run exit = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "payload failed") {
		t.Fatalf("stderr = %q, want payload failure", stderr.String())
	}
}

func TestMainSuccessPathReturns(t *testing.T) {
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })
	os.Args = []string{"telemetry-release-payload", "--endpoint"}
	main()
}

func TestMainExitsOnUsageError(t *testing.T) {
	origArgs := os.Args
	origExit := exitFn
	t.Cleanup(func() {
		os.Args = origArgs
		exitFn = origExit
	})
	os.Args = []string{"telemetry-release-payload", "extra"}
	exitFn = func(code int) {
		if code != 2 {
			t.Fatalf("exit code = %d, want 2", code)
		}
		panic("exit")
	}
	defer func() {
		if recover() != "exit" {
			t.Fatal("main did not exit")
		}
	}()
	main()
}
