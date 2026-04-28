package app

// hasp-hnf9: long socket paths must clip with a leading ellipsis on narrow
// terminals so the human-mode key/value table doesn't wrap. JSON output must
// always preserve the full path.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func TestRenderStatusHumanClipsLongSocketPathOnNarrowTerminal(t *testing.T) {
	const longPath = "/var/folders/00/abcdefghijklmnop/T/hasp-test-XXXXXXXX/run/hasp-daemon.sock"
	origColumns := terminalColumnsFn
	t.Cleanup(func() { terminalColumnsFn = origColumns })
	terminalColumnsFn = func() int { return 40 }

	var stdout bytes.Buffer
	if err := renderStatusHuman(&stdout, runtime.StatusResponse{SocketPath: longPath, PID: 42}); err != nil {
		t.Fatalf("renderStatusHuman: %v", err)
	}

	out := stdout.String()
	socketLine := findSocketLine(t, out)
	if !strings.Contains(socketLine, "…") {
		t.Fatalf("narrow-terminal output should clip with leading ellipsis; line=%q full=%q", socketLine, out)
	}
	if strings.Contains(socketLine, longPath) {
		t.Fatalf("narrow-terminal output must not contain full long path; line=%q", socketLine)
	}
	if !strings.Contains(socketLine, "hasp-daemon.sock") {
		t.Fatalf("clipped path should keep the trailing filename; line=%q", socketLine)
	}
}

func TestRenderStatusHumanLeavesShortPathAloneOnWideTerminal(t *testing.T) {
	const shortPath = "/tmp/h.sock"
	origColumns := terminalColumnsFn
	t.Cleanup(func() { terminalColumnsFn = origColumns })
	terminalColumnsFn = func() int { return 200 }

	var stdout bytes.Buffer
	if err := renderStatusHuman(&stdout, runtime.StatusResponse{SocketPath: shortPath, PID: 1}); err != nil {
		t.Fatalf("renderStatusHuman: %v", err)
	}
	if !strings.Contains(stdout.String(), shortPath) {
		t.Fatalf("wide terminal must keep the full short path; got: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "…") {
		t.Fatalf("wide terminal must not clip; got: %s", stdout.String())
	}
}

func TestRenderStatusHumanLeavesValueAloneWhenWidthUnknown(t *testing.T) {
	const longPath = "/var/folders/00/abcdefghijklmnop/T/hasp-test-XXXXXXXX/run/hasp-daemon.sock"
	origColumns := terminalColumnsFn
	t.Cleanup(func() { terminalColumnsFn = origColumns })
	// 0 means we couldn't detect the terminal — never clip in that case so we
	// don't truncate paths in CI logs or pipes.
	terminalColumnsFn = func() int { return 0 }

	var stdout bytes.Buffer
	if err := renderStatusHuman(&stdout, runtime.StatusResponse{SocketPath: longPath, PID: 1}); err != nil {
		t.Fatalf("renderStatusHuman: %v", err)
	}
	if !strings.Contains(stdout.String(), longPath) {
		t.Fatalf("unknown width must keep the full path; got: %s", stdout.String())
	}
}

func TestClipForTerminalLeavesValueAloneWhenColumnsZero(t *testing.T) {
	in := "/very/long/socket/path/that/should/not/be/clipped"
	got := clipForTerminal(in, len("socket  "), 0)
	if got != in {
		t.Fatalf("clipForTerminal with columns=0 should be a no-op; got %q want %q", got, in)
	}
}

func findSocketLine(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "socket") {
			return line
		}
	}
	t.Fatalf("no `socket` line in output:\n%s", out)
	return ""
}
