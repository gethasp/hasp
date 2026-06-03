package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestNewServerRejectsNonLoopbackBindAddress(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())

	_, err := NewServer(paths.Paths{HomeDir: t.TempDir()}, Options{
		Handler: http.NotFoundHandler(),
		V4Addr:  "0.0.0.0:0",
		V6Addr:  "",
	})
	if err == nil {
		t.Fatal("expected non-loopback bind rejection")
	}
	if !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("expected non-loopback error, got %v", err)
	}
}

func TestNewServerAndServerHelperErrorBranches(t *testing.T) {
	if _, err := NewServer(paths.Paths{}, Options{}); err == nil {
		t.Fatal("expected missing home dir error")
	}
	minimal, err := NewServer(paths.Paths{HomeDir: t.TempDir()}, Options{V6Addr: ""})
	if err != nil {
		t.Fatalf("minimal server without v6: %v", err)
	}
	if minimal.Ports().V4 == 0 || minimal.Ports().StartedAt == "" {
		t.Fatalf("minimal server ports = %+v", minimal.Ports())
	}
	if err := minimal.Close(); err != nil {
		t.Fatalf("close minimal server: %v", err)
	}
	peerServer, err := NewServer(paths.Paths{HomeDir: t.TempDir()}, Options{
		V6Addr:  "",
		PeerPID: func(net.Conn) (uint32, error) { return 1234, nil },
	})
	if err != nil {
		t.Fatalf("peer server: %v", err)
	}
	clientConn, serverConn := net.Pipe()
	ctx := peerServer.httpServer.ConnContext(context.Background(), clientConn)
	if _, err := PeerPIDFromContext(new(http.Request).WithContext(ctx)); err == nil {
		t.Fatal("non-unix connection should not receive peer pid")
	}
	_ = clientConn.Close()
	_ = serverConn.Close()
	_ = peerServer.Close()
	//lint:ignore SA1012 intentionally covers the nil-context fallback
	if err := (&Server{httpServer: &http.Server{}}).Serve(nil); err == nil { //nolint:staticcheck // intentionally covers the nil-context fallback
		t.Fatal("expected no listeners error")
	}
	if err := (&Server{httpServer: &http.Server{}, listeners: []net.Listener{fakeListener{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}}}}).Serve(context.Background()); err == nil {
		t.Fatal("expected listener serve error")
	}
	server := &Server{httpServer: &http.Server{}, portFilePath: filepath.Join(t.TempDir(), "port"), wrotePortFile: false}
	if err := server.removePortFile(); err != nil {
		t.Fatalf("remove unwritten port file: %v", err)
	}
	if got := resolvedPortFilePath(paths.Paths{HomeDir: "/tmp/hasp", HTTPPortFilePath: "/tmp/custom"}); got != "/tmp/custom" {
		t.Fatalf("resolved port file = %q", got)
	}
	if got := tcpListenerPort(fakeListener{addr: fakeAddr("pipe")}); got != 0 {
		t.Fatalf("fake listener port = %d", got)
	}
	if err := validateLoopbackListener(fakeListener{addr: fakeAddr("pipe")}); err == nil {
		t.Fatal("expected listener type rejection")
	}
	if err := validateLoopbackListener(fakeListener{addr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1}}); err == nil {
		t.Fatal("expected non-loopback listener rejection")
	}
	if err := validateLoopbackBindAddr("not-a-host-port"); err == nil {
		t.Fatal("expected bind parse error")
	}
	if err := removeStaleUnixSocket(string([]byte{'b', 'a', 'd', 0, 'p', 'a', 't', 'h'})); err == nil {
		t.Fatal("expected stat unix socket path error")
	}
	if err := removeUnixSocket(" "); err != nil {
		t.Fatalf("blank unix socket removal: %v", err)
	}
}

func TestNewServerRejectsLocalhostAlias(t *testing.T) {
	_, err := NewServer(paths.Paths{HomeDir: t.TempDir()}, Options{
		Handler: http.NotFoundHandler(),
		V4Addr:  "localhost:0",
		V6Addr:  "",
	})
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("expected localhost alias rejection, got %v", err)
	}
}

func TestHTTPServerSeamsCoverPortAndSocketFailures(t *testing.T) {
	origRemove := removeFile
	origMkdir := mkdirAll
	origOpen := openExclusiveFile
	origListenTCP := listenTCP
	origListenUnix := listenUnix
	origChmod := chmodSocket
	origPortFileMarshal := portFileMarshal
	t.Cleanup(func() {
		removeFile = origRemove
		mkdirAll = origMkdir
		openExclusiveFile = origOpen
		listenTCP = origListenTCP
		listenUnix = origListenUnix
		chmodSocket = origChmod
		portFileMarshal = origPortFileMarshal
	})

	portPath := filepath.Join(t.TempDir(), ".testsock-port")
	oldArgs0 := os.Args[0]
	os.Args[0] = "hasp.test"
	removeFile = func(string) error { return nil }
	if err := removeStaleTestPortFile(portPath); err != nil {
		t.Fatalf("stale test port removal success: %v", err)
	}
	removeFile = func(string) error { return errors.New("remove failed") }
	if err := removeStaleTestPortFile(portPath); err == nil || !strings.Contains(err.Error(), "remove stale test port file") {
		t.Fatalf("expected stale test port failure, got %v", err)
	}
	if _, err := NewServer(paths.Paths{HomeDir: t.TempDir(), HTTPPortFilePath: filepath.Join(t.TempDir(), ".testsock-port")}, Options{V6Addr: ""}); err == nil || !strings.Contains(err.Error(), "remove stale test port file") {
		t.Fatalf("expected NewServer stale test port failure, got %v", err)
	}
	os.Args[0] = oldArgs0
	removeFile = origRemove

	mkdirAll = func(string, os.FileMode) error { return errors.New("mkdir failed") }
	if err := (&Server{portFilePath: filepath.Join(t.TempDir(), "port")}).writePortFile(); err == nil {
		t.Fatal("expected writePortFile mkdir failure")
	}
	if _, err := bindUnixListener(filepath.Join(t.TempDir(), "sock")); err == nil {
		t.Fatal("expected bindUnixListener mkdir failure")
	}
	mkdirAll = origMkdir

	openExclusiveFile = func(string, int, os.FileMode) (*os.File, error) { return nil, errors.New("open failed") }
	if err := writePortFileExclusive(filepath.Join(t.TempDir(), "port"), PortFileState{}); err == nil {
		t.Fatal("expected port file open failure")
	}
	portFileMarshal = func(any) ([]byte, error) { return nil, errors.New("marshal failed") }
	if err := writePortFileExclusive(filepath.Join(t.TempDir(), "port"), PortFileState{}); err == nil {
		t.Fatal("expected port file marshal failure")
	}
	portFileMarshal = origPortFileMarshal
	dirFile, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open temp dir: %v", err)
	}
	openExclusiveFile = func(string, int, os.FileMode) (*os.File, error) { return dirFile, nil }
	if err := writePortFileExclusive(filepath.Join(t.TempDir(), "port"), PortFileState{}); err == nil {
		t.Fatal("expected port file write failure")
	}
	_ = dirFile.Close()
	openExclusiveFile = origOpen

	listenCount := 0
	listenTCP = func(string, string) (net.Listener, error) {
		listenCount++
		if listenCount == 1 {
			return fakeListener{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10001}}, nil
		}
		return nil, errors.New("listen v6 failed")
	}
	if _, err := NewServer(paths.Paths{HomeDir: t.TempDir()}, Options{}); err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("expected IPv6 bind failure, got %v", err)
	}
	listenTCP = origListenTCP

	listenTCP = func(string, string) (net.Listener, error) { return nil, errors.New("listen tcp failed") }
	if _, err := bindLoopbackListener("127.0.0.1:0"); err == nil {
		t.Fatal("expected tcp listen failure")
	}
	listenTCP = func(string, string) (net.Listener, error) {
		return fakeListener{addr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1}}, nil
	}
	if _, err := bindLoopbackListener("127.0.0.1:0"); err == nil {
		t.Fatal("expected listener validation failure")
	}
	listenTCP = origListenTCP

	if _, err := bindUnixListener(" "); err == nil {
		t.Fatal("expected empty unix socket path error")
	}
	regular := filepath.Join(t.TempDir(), "not-socket")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}
	if err := removeStaleUnixSocket(regular); err == nil {
		t.Fatal("expected non-socket refusal")
	}
	listenUnix = func(string, string) (net.Listener, error) { return nil, errors.New("listen unix failed") }
	if _, err := bindUnixListener(filepath.Join(t.TempDir(), "sock")); err == nil {
		t.Fatal("expected unix listen failure")
	}
	listenUnix = func(string, string) (net.Listener, error) { return nil, errors.New("new server unix failed") }
	if _, err := NewServer(paths.Paths{HomeDir: t.TempDir()}, Options{V6Addr: "", UnixSocketPath: filepath.Join(t.TempDir(), "sock")}); err == nil || !strings.Contains(err.Error(), "unix") {
		t.Fatalf("expected NewServer unix failure, got %v", err)
	}
	listenUnix = func(string, string) (net.Listener, error) { return fakeListener{addr: fakeAddr("unix")}, nil }
	chmodSocket = func(string, os.FileMode) error { return errors.New("chmod failed") }
	if _, err := bindUnixListener(filepath.Join(t.TempDir(), "sock")); err == nil {
		t.Fatal("expected chmod socket failure")
	}
	chmodSocket = origChmod
	listenUnix = origListenUnix

	removeFile = func(string) error { return errors.New("remove failed") }
	if err := removeUnixSocket(filepath.Join(t.TempDir(), "sock")); err == nil {
		t.Fatal("expected remove unix socket failure")
	}
	server := &Server{httpServer: &http.Server{}, portFilePath: filepath.Join(t.TempDir(), "port"), unixSocketPath: filepath.Join(t.TempDir(), "sock"), wrotePortFile: true}
	if err := server.Close(); err == nil {
		t.Fatal("expected close cleanup failure")
	}
	removeFile = func(path string) error {
		if strings.HasSuffix(path, "sock") {
			return errors.New("remove unix failed")
		}
		return nil
	}
	server = &Server{httpServer: &http.Server{}, portFilePath: filepath.Join(t.TempDir(), "port"), unixSocketPath: filepath.Join(t.TempDir(), "sock"), wrotePortFile: true}
	if err := server.Close(); err == nil || !strings.Contains(err.Error(), "remove unix failed") {
		t.Fatalf("expected unix cleanup failure, got %v", err)
	}
	removeFile = origRemove
	if err := (&Server{httpServer: &http.Server{}, listeners: []net.Listener{fakeListener{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}}}}).Serve(context.TODO()); err == nil {
		t.Fatal("expected nil-context serve listener error")
	}

	regularForBind := filepath.Join(t.TempDir(), "not-socket")
	if err := os.WriteFile(regularForBind, []byte("x"), 0o600); err != nil {
		t.Fatalf("write regular bind blocker: %v", err)
	}
	if _, err := bindUnixListener(regularForBind); err == nil {
		t.Fatal("expected bind unix stale regular-file failure")
	}
	shortDir, err := os.MkdirTemp("/tmp", "hasp-httpapi-")
	if err != nil {
		t.Fatalf("short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortDir) })
	unixPath := filepath.Join(shortDir, "sock")
	listener, err := bindUnixListener(unixPath)
	if err != nil {
		t.Fatalf("bind unix success: %v", err)
	}
	if err := removeStaleUnixSocket(unixPath); err != nil {
		t.Fatalf("remove live stale socket path: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close unix listener: %v", err)
	}
}

func TestServerUnixPeerPIDContextBranches(t *testing.T) {
	homeDir, err := os.MkdirTemp("/tmp", "hasp-httpapi-")
	if err != nil {
		t.Fatalf("short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(homeDir) })
	socketPath := filepath.Join(homeDir, "daemon.sock")
	pidCalls := 0
	seen := make(chan int, 3)
	server, err := NewServer(paths.Paths{HomeDir: homeDir, HTTPPortFilePath: filepath.Join(homeDir, ".testsock-port")}, Options{
		V6Addr:         "",
		UnixSocketPath: socketPath,
		PeerPID: func(net.Conn) (uint32, error) {
			pidCalls++
			switch pidCalls {
			case 1:
				return 0, errors.New("pid unavailable")
			case 2:
				return 0, nil
			default:
				return 4242, nil
			}
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pid, err := PeerPIDFromContext(r)
			if err != nil {
				pid = 0
			}
			seen <- pid
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	if err != nil {
		t.Fatalf("new unix server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(ctx) }()
	waitForPath(t, socketPath)

	client := &http.Client{Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}}
	for i := 0; i < 3; i++ {
		resp, err := client.Get("http://unix/")
		if err != nil {
			t.Fatalf("unix request %d: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("unix request %d status = %d", i, resp.StatusCode)
		}
	}
	for _, want := range []int{0, 0, 4242} {
		select {
		case got := <-seen:
			if got != want {
				t.Fatalf("peer pid = %d, want %d", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for peer pid observation")
		}
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("serve unix: %v", err)
	}
}

func TestServerUnixTransportWithoutPeerPIDSource(t *testing.T) {
	homeDir, err := os.MkdirTemp("/tmp", "hasp-httpapi-")
	if err != nil {
		t.Fatalf("short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(homeDir) })
	socketPath := filepath.Join(homeDir, "daemon.sock")
	seen := make(chan struct {
		unix  bool
		hasID bool
	}, 1)
	server, err := NewServer(paths.Paths{HomeDir: homeDir, HTTPPortFilePath: filepath.Join(homeDir, ".testsock-port")}, Options{
		V6Addr:         "",
		UnixSocketPath: socketPath,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, pidErr := PeerPIDFromContext(r)
			seen <- struct {
				unix  bool
				hasID bool
			}{unix: IsUnixTransport(r), hasID: pidErr == nil}
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	if err != nil {
		t.Fatalf("new unix server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(ctx) }()
	waitForPath(t, socketPath)

	client := &http.Client{Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}}
	resp, err := client.Get("http://unix/")
	if err != nil {
		t.Fatalf("unix request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unix request status = %d", resp.StatusCode)
	}
	select {
	case got := <-seen:
		if !got.unix || got.hasID {
			t.Fatalf("unix/peer pid context = %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for unix transport observation")
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("serve unix: %v", err)
	}
}

func TestServerServeWritesExclusivePortFileAndServesLoopback(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)

	server, err := NewServer(paths.Paths{HomeDir: homeDir}, Options{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}),
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ctx)
	}()

	state := waitForPortFileState(t, server.PortFilePath())
	if state.V4 == 0 {
		t.Fatal("expected IPv4 port to be recorded")
	}

	info, err := os.Stat(server.PortFilePath())
	if err != nil {
		t.Fatalf("stat port file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("port file mode = %v, want 0600", got)
	}

	assertHTTPGet(t, "http://127.0.0.1:"+itoa(state.V4)+"/health")
	if state.V6 != 0 {
		assertHTTPGet(t, "http://[::1]:"+itoa(state.V6)+"/health")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server shutdown")
	}

	if _, err := os.Stat(server.PortFilePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected port file removal, got %v", err)
	}
}

func TestServerServeRefusesExistingPortFile(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)

	portFilePath := filepath.Join(homeDir, PortFileName)
	if err := os.WriteFile(portFilePath, []byte(`{"v4":1}`), 0o600); err != nil {
		t.Fatalf("seed port file: %v", err)
	}

	server, err := NewServer(paths.Paths{HomeDir: homeDir}, Options{
		Handler: http.NotFoundHandler(),
	})
	if err == nil {
		t.Fatal("expected exclusive port-file write failure")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected os.ErrExist, got %v", err)
	}
	if server != nil {
		t.Fatal("server should not be returned when port-file write fails")
	}
}

func TestServerServeRefusesSymlinkPortFile(t *testing.T) {
	homeDir := t.TempDir()
	portFilePath := filepath.Join(homeDir, PortFileName)
	targetPath := filepath.Join(homeDir, "target")
	if err := os.WriteFile(targetPath, []byte("target"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if err := os.Symlink(targetPath, portFilePath); err != nil {
		t.Fatalf("seed symlink: %v", err)
	}

	server, err := NewServer(paths.Paths{HomeDir: homeDir}, Options{
		Handler: http.NotFoundHandler(),
	})
	if err == nil {
		t.Fatal("expected symlink port-file write failure")
	}
	if server != nil {
		t.Fatal("server should not be returned when symlink port-file write fails")
	}
	body, readErr := os.ReadFile(targetPath)
	if readErr != nil {
		t.Fatalf("read target: %v", readErr)
	}
	if string(body) != "target" {
		t.Fatalf("symlink target was modified: %q", body)
	}
}

func waitForPortFileState(t *testing.T, path string) PortFileState {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			var state PortFileState
			if err := json.Unmarshal(data, &state); err == nil {
				return state
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for port file %s", path)
	return PortFileState{}
}

func waitForPath(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func assertHTTPGet(t *testing.T, rawURL string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(rawURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out probing %s", rawURL)
}

func itoa(value int) string {
	return strconv.Itoa(value)
}

type fakeAddr string

func (a fakeAddr) Network() string { return string(a) }
func (a fakeAddr) String() string  { return string(a) }

type fakeListener struct {
	addr net.Addr
}

func (l fakeListener) Accept() (net.Conn, error) { return nil, errors.New("closed") }
func (l fakeListener) Close() error              { return nil }
func (l fakeListener) Addr() net.Addr            { return l.addr }
