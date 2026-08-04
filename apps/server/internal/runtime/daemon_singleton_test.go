//go:build unix

package runtime

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/httpapi"
	"github.com/gethasp/hasp/apps/server/internal/paths"
)

// shortRuntimeDir keeps socket paths under the ~104 byte sun_path limit, which
// t.TempDir() blows past on macOS.
func shortRuntimeDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "hasp-sg")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestAcquireDaemonLockIsExclusive(t *testing.T) {
	lockPath := paths.DaemonLockPathFor(filepath.Join(shortRuntimeDir(t), "daemon.sock"))

	release, err := acquireDaemonLock(lockPath)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	if _, err := acquireDaemonLock(lockPath); !errors.Is(err, errDaemonAlreadyRunning) {
		t.Fatalf("second acquire = %v, want errDaemonAlreadyRunning", err)
	}

	release()

	release2, err := acquireDaemonLock(lockPath)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	release2()
}

func TestAcquireDaemonLockOpenFailure(t *testing.T) {
	missingDir := filepath.Join(shortRuntimeDir(t), "no-such-dir")
	_, err := acquireDaemonLock(filepath.Join(missingDir, "daemon.sock.lock"))
	if err == nil || !strings.Contains(err.Error(), "open daemon lock") {
		t.Fatalf("acquireDaemonLock in missing dir = %v, want open daemon lock error", err)
	}
}

func TestAcquireDaemonLockFlockFailure(t *testing.T) {
	orig := daemonFlock
	daemonFlock = func(int, int) error { return syscall.EIO }
	defer func() { daemonFlock = orig }()

	_, err := acquireDaemonLock(paths.DaemonLockPathFor(filepath.Join(shortRuntimeDir(t), "daemon.sock")))
	if err == nil || !strings.Contains(err.Error(), "lock daemon") {
		t.Fatalf("acquireDaemonLock with EIO = %v, want lock daemon error", err)
	}
	if errors.Is(err, errDaemonAlreadyRunning) {
		t.Fatal("a non-EWOULDBLOCK flock error was reported as an already-running daemon")
	}
}

// nonStatFileInfo reports a Sys() that is not a *syscall.Stat_t, which os.Stat
// never produces on unix but statSocketIdentity must still refuse rather than
// panic on a bare type assertion.
type nonStatFileInfo struct{ os.FileInfo }

func (nonStatFileInfo) Sys() any { return nil }

func TestStatSocketIdentityRejectsUnexpectedStatType(t *testing.T) {
	orig := statSocketFile
	statSocketFile = func(string) (os.FileInfo, error) { return nonStatFileInfo{}, nil }
	defer func() { statSocketFile = orig }()

	if _, err := statSocketIdentity("irrelevant"); err == nil || !strings.Contains(err.Error(), "unexpected stat type") {
		t.Fatalf("statSocketIdentity = %v, want unexpected stat type error", err)
	}
}

// TestRunDaemonPropagatesLockFailure covers the non-contention lock error: the
// daemon must surface it, not treat it as "someone else is already serving".
func TestRunDaemonPropagatesLockFailure(t *testing.T) {
	runtimeDir := shortRuntimeDir(t)
	// The lock sits beside the socket, so a socket in a missing subdirectory
	// makes the lock unopenable while RuntimeDir itself is created fine.
	socketPath := filepath.Join(runtimeDir, "missing", "daemon.sock")
	manager := &Manager{paths: paths.Paths{
		HomeDir:    runtimeDir,
		RuntimeDir: runtimeDir,
		SocketPath: socketPath,
	}}

	err := manager.RunDaemon(context.Background())
	if err == nil || !strings.Contains(err.Error(), "open daemon lock") {
		t.Fatalf("RunDaemon = %v, want the lock open failure surfaced", err)
	}
}

// TestRunDaemonShutsDownWhenSocketIsStolen is the end-to-end self-heal: a fully
// started daemon whose socket gets unlinked must exit instead of serving an
// unreachable inode forever.
func TestRunDaemonShutsDownWhenSocketIsStolen(t *testing.T) {
	home := shortRuntimeDir(t)
	runtimeDir := filepath.Join(home, "runtime")
	socketPath := filepath.Join(runtimeDir, "daemon.sock")
	manager := &Manager{paths: paths.Paths{
		HomeDir:          home,
		RuntimeDir:       runtimeDir,
		SocketPath:       socketPath,
		PidFilePath:      filepath.Join(runtimeDir, "daemon.pid"),
		HTTPPortFilePath: filepath.Join(home, httpapi.PortFileName),
	}}

	orig := socketOwnershipCheckInterval
	socketOwnershipCheckInterval = 20 * time.Millisecond
	defer func() { socketOwnershipCheckInterval = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- manager.RunDaemon(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if conn, err := net.DialTimeout("unix", socketPath, 200*time.Millisecond); err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon never bound its socket")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Steal the name the way the old EnsureDaemon did.
	if err := os.Remove(socketPath); err != nil {
		t.Fatalf("unlink daemon socket: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunDaemon after losing its socket = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon kept running after its socket was unlinked")
	}
}

// TestRunDaemonLoserTouchesNothing is the regression test for hasp-20vs: a
// second daemon that loses the singleton race must leave the winner's socket,
// pid file and port file exactly as it found them.
func TestRunDaemonLoserTouchesNothing(t *testing.T) {
	runtimeDir := shortRuntimeDir(t)
	socketPath := filepath.Join(runtimeDir, "daemon.sock")
	pidFilePath := filepath.Join(runtimeDir, "daemon.pid")
	portFilePath := filepath.Join(runtimeDir, "daemon.http.port")

	// Stand in for the winner: hold the lock and plant its runtime files.
	release, err := acquireDaemonLock(paths.DaemonLockPathFor(socketPath))
	if err != nil {
		t.Fatalf("winner acquire lock: %v", err)
	}
	defer release()

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("winner listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	winnerSocket, err := statSocketIdentity(socketPath)
	if err != nil {
		t.Fatalf("stat winner socket: %v", err)
	}
	if err := os.WriteFile(pidFilePath, []byte("4242"), 0o600); err != nil {
		t.Fatalf("write winner pid file: %v", err)
	}
	if err := os.WriteFile(portFilePath, []byte(`{"v4":1}`), 0o600); err != nil {
		t.Fatalf("write winner port file: %v", err)
	}

	manager := &Manager{paths: paths.Paths{
		HomeDir:          runtimeDir,
		RuntimeDir:       runtimeDir,
		SocketPath:       socketPath,
		PidFilePath:      pidFilePath,
		DaemonLockPath:   paths.DaemonLockPathFor(socketPath),
		HTTPPortFilePath: portFilePath,
	}}

	if err := manager.RunDaemon(context.Background()); err != nil {
		t.Fatalf("loser RunDaemon = %v, want nil", err)
	}

	// The winner's socket must still be the same inode, not a replacement.
	after, err := statSocketIdentity(socketPath)
	if err != nil {
		t.Fatalf("winner socket gone after losing run: %v", err)
	}
	if after != winnerSocket {
		t.Fatal("loser replaced the winner's socket inode")
	}
	pid, err := os.ReadFile(pidFilePath)
	if err != nil || string(pid) != "4242" {
		t.Fatalf("pid file = %q, %v; want winner's 4242 intact", pid, err)
	}
	port, err := os.ReadFile(portFilePath)
	if err != nil || string(port) != `{"v4":1}` {
		t.Fatalf("port file = %q, %v; want winner's content intact", port, err)
	}
}

// TestAcquireSingletonLockWaitsOutADyingDaemon covers the retry: `hasp daemon
// stop` returns once it has signalled the incumbent, so the next daemon can
// find the lock still held for a few milliseconds. It must wait, not exit.
func TestAcquireSingletonLockWaitsOutADyingDaemon(t *testing.T) {
	runtimeDir := shortRuntimeDir(t)
	socketPath := filepath.Join(runtimeDir, "daemon.sock")
	lockPath := paths.DaemonLockPathFor(socketPath)
	manager := &Manager{paths: paths.Paths{
		HomeDir:        runtimeDir,
		RuntimeDir:     runtimeDir,
		SocketPath:     socketPath,
		DaemonLockPath: lockPath,
	}}

	release, err := acquireDaemonLock(lockPath)
	if err != nil {
		t.Fatalf("incumbent acquire lock: %v", err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		release()
	}()

	got, err := manager.acquireSingletonLock(context.Background())
	if err != nil {
		t.Fatalf("acquireSingletonLock = %v, want the lock after the incumbent let go", err)
	}
	if got == nil {
		t.Fatal("acquireSingletonLock returned no release func and no error")
	}
	got()
}

// TestAcquireSingletonLockFailsWhenHolderIsNotServing is the anti-silent-exit
// case: returning nil here would look exactly like a successful start while
// leaving the caller to wait out its startup timeout.
func TestAcquireSingletonLockFailsWhenHolderIsNotServing(t *testing.T) {
	runtimeDir := shortRuntimeDir(t)
	socketPath := filepath.Join(runtimeDir, "daemon.sock")
	lockPath := paths.DaemonLockPathFor(socketPath)
	manager := &Manager{paths: paths.Paths{
		HomeDir:        runtimeDir,
		RuntimeDir:     runtimeDir,
		SocketPath:     socketPath,
		DaemonLockPath: lockPath,
	}}

	release, err := acquireDaemonLock(lockPath)
	if err != nil {
		t.Fatalf("holder acquire lock: %v", err)
	}
	defer release()

	origWait := daemonLockWaitTimeout
	daemonLockWaitTimeout = 40 * time.Millisecond
	defer func() { daemonLockWaitTimeout = origWait }()

	got, err := manager.acquireSingletonLock(context.Background())
	if got != nil {
		t.Fatal("acquireSingletonLock handed out a lock nobody released")
	}
	if err == nil || !strings.Contains(err.Error(), "nothing is listening on") {
		t.Fatalf("acquireSingletonLock = %v, want the not-serving holder named", err)
	}
}

// TestAcquireSingletonLockHonoursContext stops the wait early rather than
// spinning for the full timeout after the caller has given up.
func TestAcquireSingletonLockHonoursContext(t *testing.T) {
	runtimeDir := shortRuntimeDir(t)
	socketPath := filepath.Join(runtimeDir, "daemon.sock")
	lockPath := paths.DaemonLockPathFor(socketPath)
	manager := &Manager{paths: paths.Paths{
		HomeDir:        runtimeDir,
		RuntimeDir:     runtimeDir,
		SocketPath:     socketPath,
		DaemonLockPath: lockPath,
	}}

	release, err := acquireDaemonLock(lockPath)
	if err != nil {
		t.Fatalf("holder acquire lock: %v", err)
	}
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := manager.acquireSingletonLock(ctx)
	if got != nil {
		t.Fatal("acquireSingletonLock handed out a lock nobody released")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("acquireSingletonLock = %v, want context.Canceled", err)
	}
}

// TestEnsureDaemonKeepsLiveSocketWhenDialTimesOut is the second half of the
// startup wedge: a dial that lost its own narrow deadline is not evidence that
// the socket is stale, and unlinking it here left the incumbent holding the
// singleton lock with no reachable socket for anyone.
func TestEnsureDaemonKeepsLiveSocketWhenDialTimesOut(t *testing.T) {
	runtimeDir := shortRuntimeDir(t)
	socketPath := filepath.Join(runtimeDir, "daemon.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	before, err := statSocketIdentity(socketPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}

	manager := &Manager{paths: paths.Paths{
		HomeDir:          runtimeDir,
		RuntimeDir:       runtimeDir,
		SocketPath:       socketPath,
		PidFilePath:      filepath.Join(runtimeDir, "daemon.pid"),
		HTTPPortFilePath: filepath.Join(runtimeDir, httpapi.PortFileName),
	}}

	// A caller whose budget is already spent: Dial fails, but the socket is as
	// live as it gets.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := manager.EnsureDaemon(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("EnsureDaemon = %v, want context.Canceled", err)
	}
	after, err := statSocketIdentity(socketPath)
	if err != nil {
		t.Fatalf("socket gone after a timed-out dial: %v", err)
	}
	if after != before {
		t.Fatal("EnsureDaemon replaced a live socket after its dial timed out")
	}
}

func TestRemoveStaleSocketRefusesLiveListener(t *testing.T) {
	socketPath := filepath.Join(shortRuntimeDir(t), "daemon.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	if err := removeStaleSocket(socketPath); err == nil {
		t.Fatal("removeStaleSocket removed a socket with a live listener")
	}
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("live socket was unlinked: %v", err)
	}
}

func TestRemoveStaleSocketRemovesAbandonedSocket(t *testing.T) {
	socketPath := abandonUnixSocket(t, shortRuntimeDir(t))
	if err := removeStaleSocket(socketPath); err != nil {
		t.Fatalf("removeStaleSocket on abandoned socket = %v", err)
	}
	if _, err := os.Stat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abandoned socket survived: %v", err)
	}
}

// TestEnsureDaemonRefusesToStealLiveSocket covers the other half of hasp-20vs:
// EnsureDaemon used to unlink a socket whose listener failed verification,
// stranding that listener forever.
func TestEnsureDaemonRefusesToStealLiveSocket(t *testing.T) {
	runtimeDir := shortRuntimeDir(t)
	socketPath := filepath.Join(runtimeDir, "daemon.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close() // answers, but never speaks HASP
		}
	}()

	spawned := false
	origSpawn := spawnDaemonProcess
	spawnDaemonProcess = func(context.Context) error {
		spawned = true
		return nil
	}
	defer func() { spawnDaemonProcess = origSpawn }()

	manager := &Manager{paths: paths.Paths{
		HomeDir:    runtimeDir,
		RuntimeDir: runtimeDir,
		SocketPath: socketPath,
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = manager.EnsureDaemon(ctx)
	if err == nil {
		t.Fatal("EnsureDaemon accepted an unverified listener")
	}
	if spawned {
		t.Fatal("EnsureDaemon spawned a replacement instead of refusing")
	}
	if _, statErr := os.Stat(socketPath); statErr != nil {
		t.Fatalf("EnsureDaemon unlinked the live socket: %v", statErr)
	}
}

func TestDaemonOwnsPidFile(t *testing.T) {
	dir := shortRuntimeDir(t)
	pidFilePath := filepath.Join(dir, "daemon.pid")

	if daemonOwnsPidFile(pidFilePath) {
		t.Fatal("missing pid file reported as owned")
	}
	if err := os.WriteFile(pidFilePath, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
	if !daemonOwnsPidFile(pidFilePath) {
		t.Fatal("own pid file reported as not owned")
	}
	if err := os.WriteFile(pidFilePath, []byte(strconv.Itoa(os.Getpid()+1)), 0o600); err != nil {
		t.Fatalf("rewrite pid file: %v", err)
	}
	if daemonOwnsPidFile(pidFilePath) {
		t.Fatal("another process's pid file reported as owned")
	}
	if err := os.WriteFile(pidFilePath, []byte("not-a-pid"), 0o600); err != nil {
		t.Fatalf("write garbage pid file: %v", err)
	}
	if daemonOwnsPidFile(pidFilePath) {
		t.Fatal("unparseable pid file reported as owned")
	}
}

func TestDaemonOwnsSocketDetectsReplacement(t *testing.T) {
	socketPath := filepath.Join(shortRuntimeDir(t), "daemon.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	own, err := statSocketIdentity(socketPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !daemonOwnsSocket(socketPath, own) {
		t.Fatal("own socket reported as not owned")
	}

	// Simulate the theft: unlink our socket and bind a replacement at the path.
	if err := os.Remove(socketPath); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	replacement, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("rebind: %v", err)
	}
	defer func() { _ = replacement.Close() }()

	if daemonOwnsSocket(socketPath, own) {
		t.Fatal("replacement socket reported as ours")
	}
}

// TestWatchSocketOwnershipSignalsLoss proves the self-heal: a daemon whose
// socket got unlinked and replaced is told to shut down instead of idling
// unreachable forever.
func TestWatchSocketOwnershipSignalsLoss(t *testing.T) {
	socketPath := filepath.Join(shortRuntimeDir(t), "daemon.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	own, err := statSocketIdentity(socketPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	orig := socketOwnershipCheckInterval
	socketOwnershipCheckInterval = 10 * time.Millisecond
	defer func() { socketOwnershipCheckInterval = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lost := make(chan struct{})
	go watchSocketOwnership(ctx, socketPath, own, lost)

	if err := os.Remove(socketPath); err != nil {
		t.Fatalf("unlink: %v", err)
	}

	select {
	case <-lost:
	case <-time.After(3 * time.Second):
		t.Fatal("watchSocketOwnership never reported the lost socket")
	}
}

// TestWatchSocketOwnershipStopsWhenNobodyListens covers the watchdog losing its
// race with shutdown: the socket is gone but RunDaemon has already returned, so
// nothing reads the channel and the goroutine must exit on ctx instead of
// parking on the send forever.
func TestWatchSocketOwnershipStopsWhenNobodyListens(t *testing.T) {
	socketPath := filepath.Join(shortRuntimeDir(t), "daemon.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	own, err := statSocketIdentity(socketPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	orig := socketOwnershipCheckInterval
	socketOwnershipCheckInterval = 10 * time.Millisecond
	defer func() { socketOwnershipCheckInterval = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		// Unbuffered and never read: the watchdog blocks on the send.
		watchSocketOwnership(ctx, socketPath, own, make(chan struct{}))
		close(done)
	}()

	if err := os.Remove(socketPath); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	// Give the watchdog time to notice and park on the unread send.
	time.Sleep(100 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("watchdog returned before the send could block")
	default:
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("watchSocketOwnership stayed parked on the send after cancel")
	}
}

func TestWatchSocketOwnershipStaysQuietWhileOwned(t *testing.T) {
	socketPath := filepath.Join(shortRuntimeDir(t), "daemon.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	own, err := statSocketIdentity(socketPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	orig := socketOwnershipCheckInterval
	socketOwnershipCheckInterval = 10 * time.Millisecond
	defer func() { socketOwnershipCheckInterval = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lost := make(chan struct{})
	go watchSocketOwnership(ctx, socketPath, own, lost)

	select {
	case <-lost:
		t.Fatal("watchSocketOwnership reported loss while still owning the socket")
	case <-time.After(200 * time.Millisecond):
	}
}
