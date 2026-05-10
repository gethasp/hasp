package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

const (
	DefaultV4Addr = "127.0.0.1:0"
	DefaultV6Addr = "[::1]:0"
	PortFileName  = "daemon.http.port"
)

var (
	listenTCP         = net.Listen
	listenUnix        = net.Listen
	mkdirAll          = os.MkdirAll
	chmodSocket       = os.Chmod
	openExclusiveFile = os.OpenFile
	removeFile        = os.Remove
	nowUTC            = func() time.Time { return time.Now().UTC() }
)

type Options struct {
	Handler        http.Handler
	Validator      *Validator
	V4Addr         string
	V6Addr         string
	UnixSocketPath string
	PeerPID        func(net.Conn) (uint32, error)
	StartedAt      time.Time
}

type PortFileState struct {
	V4         int    `json:"v4"`
	V6         int    `json:"v6"`
	UnixSocket string `json:"unix_socket,omitempty"`
	StartedAt  string `json:"started_at"`
}

type Server struct {
	httpServer     *http.Server
	listeners      []net.Listener
	portFilePath   string
	unixSocketPath string
	portState      PortFileState

	closeOnce     sync.Once
	wrotePortFile bool
}

func NewServer(runtimePaths paths.Paths, opts Options) (*Server, error) {
	if strings.TrimSpace(runtimePaths.HomeDir) == "" {
		return nil, errors.New("httpapi: home dir is required")
	}

	handler := opts.Handler
	if handler == nil {
		handler = http.NotFoundHandler()
	}
	if opts.Validator != nil {
		handler = opts.Validator.Middleware(handler)
	}

	startedAt := opts.StartedAt.UTC()
	if startedAt.IsZero() {
		startedAt = nowUTC()
	}

	v4Addr := opts.V4Addr
	if v4Addr == "" {
		v4Addr = DefaultV4Addr
	}
	v6Addr := opts.V6Addr
	if v6Addr == "" {
		v6Addr = DefaultV6Addr
	}

	portFilePath := resolvedPortFilePath(runtimePaths)
	if err := removeStaleTestPortFile(portFilePath); err != nil {
		return nil, err
	}

	var listeners []net.Listener
	var v4Port int
	var v6Port int

	v4Listener, err := bindLoopbackListener(v4Addr)
	if err != nil {
		return nil, fmt.Errorf("bind IPv4 loopback listener: %w", err)
	}
	listeners = append(listeners, v4Listener)
	v4Port = tcpListenerPort(v4Listener)

	if v6Addr != "" {
		v6Listener, err := bindLoopbackListener(v6Addr)
		if err != nil {
			closeListeners(listeners)
			return nil, fmt.Errorf("bind IPv6 loopback listener: %w", err)
		}
		listeners = append(listeners, v6Listener)
		v6Port = tcpListenerPort(v6Listener)
	}
	if strings.TrimSpace(opts.UnixSocketPath) != "" {
		unixListener, err := bindUnixListener(opts.UnixSocketPath)
		if err != nil {
			closeListeners(listeners)
			return nil, fmt.Errorf("bind unix listener: %w", err)
		}
		listeners = append(listeners, unixListener)
	}

	server := &Server{
		httpServer: &http.Server{
			Handler: handler,
			ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
				if opts.PeerPID == nil {
					return ctx
				}
				if _, ok := conn.(*net.UnixConn); !ok {
					return ctx
				}
				pid, err := opts.PeerPID(conn)
				if err != nil || pid == 0 {
					return ctx
				}
				return WithPeerPID(ctx, int(pid))
			},
		},
		listeners:      listeners,
		portFilePath:   portFilePath,
		unixSocketPath: strings.TrimSpace(opts.UnixSocketPath),
		portState: PortFileState{
			V4:         v4Port,
			V6:         v6Port,
			UnixSocket: strings.TrimSpace(opts.UnixSocketPath),
			StartedAt:  startedAt.Format(time.RFC3339Nano),
		},
	}
	if err := server.writePortFile(); err != nil {
		closeListeners(listeners)
		_ = removeUnixSocket(server.unixSocketPath)
		return nil, err
	}
	return server, nil
}

func resolvedPortFilePath(runtimePaths paths.Paths) string {
	if runtimePaths.HTTPPortFilePath != "" {
		return runtimePaths.HTTPPortFilePath
	}
	return filepath.Join(runtimePaths.HomeDir, PortFileName)
}

func removeStaleTestPortFile(path string) error {
	if !strings.HasSuffix(os.Args[0], ".test") || !strings.Contains(path, ".testsock") {
		return nil
	}
	if err := removeFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale test port file: %w", err)
	}
	return nil
}

func (s *Server) PortFilePath() string {
	return s.portFilePath
}

func (s *Server) Ports() PortFileState {
	return s.portState
}

func (s *Server) Serve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(s.listeners) == 0 {
		return errors.New("httpapi: no listeners configured")
	}
	defer func() { _ = s.removePortFile() }()
	defer func() { _ = s.removeUnixSocket() }()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-done:
		}
	}()

	errCh := make(chan error, len(s.listeners))
	for _, listener := range s.listeners {
		go func(l net.Listener) {
			err := s.httpServer.Serve(l)
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errCh <- err
		}(listener)
	}

	var serveErr error
	for range s.listeners {
		if err := <-errCh; err != nil && serveErr == nil {
			serveErr = err
			_ = s.Close()
		}
	}
	return serveErr
}

func (s *Server) writePortFile() error {
	if err := mkdirAll(filepath.Dir(s.portFilePath), 0o700); err != nil {
		return fmt.Errorf("create port file directory: %w", err)
	}
	if err := writePortFileExclusive(s.portFilePath, s.portState); err != nil {
		return fmt.Errorf("write port file: %w", err)
	}
	s.wrotePortFile = true
	return nil
}

func (s *Server) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		closeErr = s.httpServer.Close()
		if errors.Is(closeErr, http.ErrServerClosed) {
			closeErr = nil
		}
		if err := s.removePortFile(); err != nil && closeErr == nil {
			closeErr = err
		}
		if err := s.removeUnixSocket(); err != nil && closeErr == nil {
			closeErr = err
		}
	})
	return closeErr
}

func (s *Server) removePortFile() error {
	if !s.wrotePortFile {
		return nil
	}
	if err := removeFile(s.portFilePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Server) removeUnixSocket() error {
	return removeUnixSocket(s.unixSocketPath)
}

func writePortFileExclusive(path string, state PortFileState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal port file: %w", err)
	}
	file, err := openExclusiveFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return nil
}

func bindLoopbackListener(addr string) (net.Listener, error) {
	if err := validateLoopbackBindAddr(addr); err != nil {
		return nil, err
	}
	listener, err := listenTCP("tcp", addr)
	if err != nil {
		return nil, err
	}
	if err := validateLoopbackListener(listener); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func bindUnixListener(path string) (net.Listener, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("unix socket path is required")
	}
	if err := mkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create unix socket directory: %w", err)
	}
	if err := removeStaleUnixSocket(path); err != nil {
		return nil, err
	}
	listener, err := listenUnix("unix", path)
	if err != nil {
		return nil, err
	}
	if err := chmodSocket(path, 0o600); err != nil {
		_ = listener.Close()
		_ = removeUnixSocket(path)
		return nil, fmt.Errorf("chmod unix socket: %w", err)
	}
	return listener, nil
}

func removeStaleUnixSocket(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat unix socket path: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket file at %s", path)
	}
	return removeUnixSocket(path)
}

func removeUnixSocket(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := removeFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func validateLoopbackBindAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse bind address %q: %w", addr, err)
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("refusing non-loopback bind address %q", addr)
	}
	return nil
}

func validateLoopbackListener(listener net.Listener) error {
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("unexpected listener type %T", listener.Addr())
	}
	if tcpAddr.IP == nil || !tcpAddr.IP.IsLoopback() {
		return fmt.Errorf("listener bound to non-loopback address %q", listener.Addr().String())
	}
	return nil
}

func closeListeners(listeners []net.Listener) {
	for _, listener := range listeners {
		_ = listener.Close()
	}
}

func tcpListenerPort(listener net.Listener) int {
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0
	}
	return tcpAddr.Port
}
