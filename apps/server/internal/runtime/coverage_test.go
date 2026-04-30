package runtime

import (
	"errors"
	"net"
	"net/rpc"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestRuntimeCoverageServerAndLineageBranches(t *testing.T) {
	if peerSharesLineage(0, os.Getpid()) {
		t.Fatal("zero peer PID should not share lineage")
	}
	if peerSharesLineage(uint32(os.Getpid()), -1) {
		t.Fatal("invalid request PID should not share lineage")
	}

	cmd := exec.Command("sh", "-c", "sleep 1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	if !peerSharesLineage(uint32(os.Getpid()), cmd.Process.Pid) {
		t.Fatal("parent peer should share lineage with child request")
	}
	if !peerSharesLineage(uint32(cmd.Process.Pid), os.Getpid()) {
		t.Fatal("child peer should share lineage with parent request")
	}

	server := &rpcServer{auditState: newAuditState(nil)}
	server.appendPeerRejectAudit(map[string]any{"reason": "test"})
	degraded, _ := server.auditState.Snapshot()
	if !degraded {
		t.Fatal("nil audit logger should mark audit degraded")
	}

	lockRuntimeSeams(t)
	origRegister := registerServerName
	registerServerName = func(*rpc.Server, string, any) error { return errors.New("register") }
	t.Cleanup(func() { registerServerName = origRegister })
	c1, c2 := net.Pipe()
	defer c2.Close()
	server = &rpcServer{
		paths:      paths.Paths{SocketPath: "pipe"},
		startedAt:  time.Now(),
		sessions:   NewSessionStore(),
		auditState: newAuditState(nil),
	}
	server.serveConn(c1, uint32(os.Getpid()))
	if _, err := c2.Write([]byte("x")); err == nil {
		t.Fatal("expected peer connection to close after register error")
	}
	registerServerName = origRegister
}

func TestRuntimeCoverageDefaultGitTopLevelSuccess(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	repo := t.TempDir()
	cmd := exec.Command("git", "init", repo)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	subdir := filepath.Join(repo, "nested")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	want, err := filepath.EvalSymlinks(repo)
	if err != nil {
		t.Fatalf("eval repo: %v", err)
	}
	got := CanonicalProjectRoot(subdir)
	if got != want {
		t.Fatalf("CanonicalProjectRoot = %q, want %q", got, want)
	}
}
